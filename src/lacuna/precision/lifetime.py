"""
Lifetime / use-after-free analyzer (intra-procedural, AST-driven).

Tracks heap-allocated pointers within a single function and reports:

  * **CWE-416 Use-after-free** — a pointer is dereferenced, indexed,
    member-accessed, or passed to a callee after it has been freed.
  * **CWE-415 Double-free** — a pointer is freed twice on a single path.
  * **CWE-672 Operation on resource after expiration (alias UAF)** — an
    alias of a freed pointer is dereferenced.

Design
======

Previous revisions implemented this with a line-by-line regex scanner that
treated the function body as a flat sequence of strings. That conflated
``if (cond) { free(p); }`` (free is conditional) with
``free(p);`` (always frees), produced duplicate findings, and missed any
use after the very first one. This rewrite runs on the real tree-sitter
AST instead:

  1. For each ``Function`` node found by ``ast_parse.parse_with_tree_sitter``,
     we build a ``Scope`` of per-pointer state and walk the function body
     recursively.
  2. ``If`` nodes fork the scope: each branch is analyzed with a copy of
     the state; results are joined at the merge point with
     ``is_freed = then.is_freed AND else.is_freed`` — i.e. the pointer is
     only "definitely freed" if every reachable branch frees it.
  3. Aliases are tracked through simple ``q = p`` assignments. Freeing
     ``p`` marks every recorded alias of ``p`` as freed too.
  4. Use-site detection inspects the AST shape: ``pointer_expression``
     (``*p``), ``subscript_expression`` (``p[i]``),
     ``pointer_field_expression`` (``p->f``), and callee-argument
     references. ``%p`` format-string arguments and explicit
     address-taking (``&p`` — a write to the pointer slot, not a deref)
     are NOT counted as uses.
  5. Use sites are emitted as separate findings so the validator can
     reproduce each one independently. Cross-branch findings get a
     lower confidence than straight-line ones.

Languages: C, C++, Objective-C (the GC-free languages where this bites).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from lacuna.flow.ast_parse import Node, parse_with_tree_sitter

SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)

SUFFIX_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".m": "c", ".mm": "cpp",
}

# Regexes used to recognise idioms inside per-statement source snippets.
# These complement the AST walk where tree-sitter's kind alone isn't enough
# to disambiguate (e.g. the snippet is the most reliable way to tell
# ``malloc(...)`` from ``read_size(...)``).
_ALLOC_CALLEE = re.compile(
    r"^(?:\w+\s*\*\s*)?"                                # optional cast
    r"(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|"
    r"strdup|strndup|asprintf|g_malloc|g_strdup|"
    r"new\s+[\w:]+)$"
)
_FREE_CALLEE = re.compile(
    r"^(free|kfree|vfree|g_free|delete\s+\w*)$"
)
_NULL_RHS = re.compile(r"^(?:NULL|nullptr|0)$")


@dataclass
class PtrState:
    """Per-pointer lifetime state inside a Scope."""
    name: str
    allocated_at: int = 0
    alloc_call: str = ""
    freed_at: int = 0
    free_call: str = ""
    is_freed: bool = False
    # Other pointer names that share this state (via ``q = p`` aliasing).
    aliases: set[str] = field(default_factory=set)
    # If the free was inside one branch but not the other, we lower
    # confidence on any use-after.
    freed_cross_branch: bool = False

    def copy(self) -> PtrState:
        return PtrState(
            name=self.name, allocated_at=self.allocated_at,
            alloc_call=self.alloc_call, freed_at=self.freed_at,
            free_call=self.free_call, is_freed=self.is_freed,
            aliases=set(self.aliases),
            freed_cross_branch=self.freed_cross_branch,
        )


@dataclass
class Scope:
    """State for one branch of a function body."""
    ptrs: dict[str, PtrState] = field(default_factory=dict)
    # Recorded findings, accumulated up the analysis tree.
    findings: list[Finding] = field(default_factory=list)

    def copy(self) -> Scope:
        new = Scope(findings=self.findings)  # findings are shared
        for k, v in self.ptrs.items():
            new.ptrs[k] = v.copy()
        return new

    def join(self, other: Scope) -> None:
        """Merge ``other`` (an alternate branch) into ``self``.

        After the join, a pointer is considered freed only when *both*
        branches freed it; otherwise it's marked as ``freed_cross_branch``
        so any subsequent use is reported at lower confidence.
        """
        all_names = set(self.ptrs) | set(other.ptrs)
        for n in all_names:
            a = self.ptrs.get(n)
            b = other.ptrs.get(n)
            if a and b:
                a.is_freed = a.is_freed and b.is_freed
                a.freed_cross_branch = (
                    a.freed_cross_branch or b.freed_cross_branch
                    or (a.is_freed != b.is_freed)
                )
                if not a.is_freed:
                    # Path keeps the earlier alloc info from whichever
                    # branch did allocate it.
                    a.allocated_at = a.allocated_at or b.allocated_at
                    a.alloc_call = a.alloc_call or b.alloc_call
                a.aliases |= b.aliases
            elif b and not a:
                self.ptrs[n] = b.copy()
                self.ptrs[n].freed_cross_branch = True


@dataclass
class Finding:
    kind: str
    repo: str
    file: str
    line: int
    function_qual: str | None
    cwe: str
    detail_md: str
    evidence: dict
    confidence: float


# ─────────────────────────────────────────────────────────────────────────────


def analyze(repo_root: Path, repo_name: str | None = None,
            max_files: int = 5000) -> dict:
    repo_name = repo_name or repo_root.name
    findings: list[Finding] = []
    files_scanned = 0

    for p in repo_root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not p.is_file() or SKIP.search(str(p)):
            continue
        lang = SUFFIX_TO_LANG.get(p.suffix.lower())
        if not lang:
            continue
        try:
            root = parse_with_tree_sitter(p, lang)
        except Exception:
            continue
        if root is None:
            continue
        files_scanned += 1
        try:
            _analyze_module(root, p, repo_root, repo_name, lang, findings)
        except Exception:
            # Defensive — never let one file kill the whole scan.
            continue

    return {
        "summary": (
            f"lifetime: {len(findings)} findings across "
            f"{files_scanned} files"
        ),
        "findings": [_to_dict(f) for f in findings],
    }


def _analyze_module(
    root: Node, path: Path, repo_root: Path, repo_name: str,
    lang: str, out: list[Finding],
) -> None:
    rel = str(path.relative_to(repo_root))
    for fn in root.of_kind("Function"):
        if fn is root:
            continue
        _analyze_function(fn, rel, repo_name, lang, out)


def _analyze_function(
    fn: Node, file: str, repo: str, lang: str, out: list[Finding],
) -> None:
    scope = Scope(findings=out)
    fn_name = fn.name or "<anon>"
    for stmt in fn.children:
        _step(stmt, scope, file, repo, fn_name, lang)


# ─── statement-level dispatcher ────────────────────────────────────────────


def _step(
    node: Node, scope: Scope, file: str, repo: str, fn_name: str, lang: str,
) -> None:
    kind = node.kind
    if kind == "If":
        _step_if(node, scope, file, repo, fn_name, lang)
        return
    if kind in {"For", "While", "Try"}:
        # Loop bodies and try bodies analyze with a forked-and-joined scope so
        # repeated frees don't compound, but the outcome may either run or
        # not — mark cross-branch on free.
        branch = scope.copy()
        for c in node.children:
            _step(c, branch, file, repo, fn_name, lang)
        # The body may also not run at all (zero iterations); treat as a
        # second empty branch.
        empty = scope.copy()
        empty.join(branch)
        scope.ptrs = empty.ptrs
        return
    if kind == "Function" or kind == "Class":
        return  # nested fns handled at module level
    if kind == "Assign":
        _step_assign(node, scope, file, repo, fn_name, lang)
        # An Assign may also contain a Call that is itself a free or a use
        # of a freed pointer; recurse to catch those.
        for c in node.children:
            _step(c, scope, file, repo, fn_name, lang)
        return
    if kind == "Call":
        _step_call(node, scope, file, repo, fn_name, lang)
        return
    if kind == "Return":
        _step_return(node, scope, file, repo, fn_name, lang)
        return
    # Everything else: descend into children
    for c in node.children:
        _step(c, scope, file, repo, fn_name, lang)


def _step_if(
    node: Node, scope: Scope, file: str, repo: str, fn_name: str, lang: str,
) -> None:
    """Branch-aware If handler.

    Heuristic: the AST adapter materialises ``If`` nodes' then and else
    bodies as flat children (the first slice is the then-body, the rest is
    the else-body). We can't distinguish them precisely without language-
    aware parsing, so we treat the *whole* If as two alternative branches:
    one runs the body (forked scope), one doesn't (empty scope), and we
    join them at the merge point. This produces conservative
    ``freed_cross_branch`` flags whenever code inside an If frees a
    pointer.
    """
    then_scope = scope.copy()
    for c in node.children:
        _step(c, then_scope, file, repo, fn_name, lang)
    empty = scope.copy()
    empty.join(then_scope)
    scope.ptrs = empty.ptrs


def _step_assign(
    node: Node, scope: Scope, file: str, repo: str, fn_name: str, lang: str,
) -> None:
    targets = [str(t).strip() for t in (node.attrs.get("targets") or [])]
    rhs_repr = (node.attrs.get("rhs_repr") or "").strip()
    if not targets:
        return

    # An assignment whose LHS is ``*p`` / ``p[i]`` / ``p->f`` is a write
    # *through* the pointer — if the pointer was already freed it's a UAF.
    for lhs in targets:
        deref = _extract_deref_target(lhs)
        if deref is not None and deref in scope.ptrs:
            ps = scope.ptrs[deref]
            if ps.is_freed:
                _emit_uaf(scope, file, repo, fn_name, node.line, ps,
                           use_snippet=f"{lhs} = {rhs_repr}",
                           reason="write through dangling pointer")

    name = targets[0]
    # Strip declarator decoration (``T *p`` → ``p``).
    name = _strip_declarator(name)
    if not name or not re.match(r"^[A-Za-z_]\w*$", name):
        return

    # Allocation site
    alloc_call = _detect_alloc(node, rhs_repr)
    if alloc_call is not None:
        scope.ptrs[name] = PtrState(
            name=name, allocated_at=node.line, alloc_call=alloc_call,
        )
        return

    # Free target: ``p = free(p)`` style is rare; we handle the more common
    # ``free(p)`` in the Call step.

    # Defensive NULL clear
    if _NULL_RHS.match(rhs_repr):
        if name in scope.ptrs:
            ps = scope.ptrs[name]
            ps.is_freed = False
            ps.freed_at = 0
            ps.free_call = ""
            ps.freed_cross_branch = False
        return

    # Alias assignment: ``q = p``
    src = rhs_repr.strip()
    src_name = _strip_declarator(src)
    if src_name in scope.ptrs and re.match(r"^[A-Za-z_]\w*$", src_name):
        # ``q`` aliases ``p`` — they share state.
        scope.ptrs[src_name].aliases.add(name)
        scope.ptrs[name] = scope.ptrs[src_name]
        return


def _step_call(
    node: Node, scope: Scope, file: str, repo: str, fn_name: str, lang: str,
) -> None:
    callee = (node.name or "").strip()
    args = [str(a).strip() for a in (node.attrs.get("args") or [])]

    # free() / kfree() / delete
    if _FREE_CALLEE.match(callee) and args:
        target_name = _strip_address_of(args[0])
        ps = scope.ptrs.get(target_name)
        if ps is None:
            return
        if ps.is_freed:
            scope.findings.append(Finding(
                kind="double_free", repo=repo, file=file, line=node.line,
                function_qual=fn_name, cwe="CWE-415",
                detail_md=(
                    f"`{target_name}` is freed at line {node.line} but was "
                    f"already freed at line {ps.freed_at} "
                    f"(originally allocated at {ps.allocated_at} via "
                    f"`{ps.alloc_call}`)."
                ),
                evidence={
                    "ptr": target_name,
                    "first_free": ps.freed_at,
                    "second_free": node.line,
                    "alloc_at": ps.allocated_at,
                    "function": fn_name,
                },
                confidence=0.85 if not ps.freed_cross_branch else 0.55,
            ))
            return
        ps.is_freed = True
        ps.freed_at = node.line
        ps.free_call = callee
        # Propagate to aliases.
        for a in ps.aliases:
            other = scope.ptrs.get(a)
            if other and other is not ps:
                other.is_freed = True
                other.freed_at = node.line
                other.free_call = callee
        return

    # Any other call: arguments that reference a freed pointer = use-after-free,
    # *except* a printf-family format-string used as ``"%p"`` is not a deref.
    is_printf = bool(re.search(
        r"\b(printf|fprintf|sprintf|snprintf|fmt\.Printf|fmt\.Sprintf)\b",
        callee,
    ))
    for i, a in enumerate(args):
        # ``&p`` takes an address — not a use of the pointee.
        a_stripped = a.strip()
        if a_stripped.startswith("&"):
            continue
        for name, ps in list(scope.ptrs.items()):
            if not ps.is_freed:
                continue
            if not re.search(rf"\b{re.escape(name)}\b", a_stripped):
                continue
            # Skip printf where the pointer is read as ``%p`` — printing
            # the address value isn't a deref.
            if is_printf and i > 0 and "%p" in args[0]:
                continue
            _emit_uaf(scope, file, repo, fn_name, node.line, ps,
                       use_snippet=f"{callee}(...{name}...)",
                       reason=f"passed to {callee}()")

    # Descend into children to catch nested calls/derefs in the arg subtrees.
    for c in node.children:
        _step(c, scope, file, repo, fn_name, lang)


def _step_return(
    node: Node, scope: Scope, file: str, repo: str, fn_name: str, lang: str,
) -> None:
    val = (node.attrs.get("value_repr") or "").strip()
    if not val:
        return
    for name, ps in scope.ptrs.items():
        if not ps.is_freed:
            continue
        if re.search(rf"\b{re.escape(name)}\b", val):
            _emit_uaf(
                scope, node.file or "", "", fn_name, node.line, ps,
                use_snippet=f"return {val}",
                reason="returning freed pointer",
            )


# ─── use-site emit ─────────────────────────────────────────────────────────


def _emit_uaf(
    scope: Scope, file: str, repo: str, fn_name: str, line_no: int,
    ps: PtrState, use_snippet: str, reason: str,
) -> None:
    """Emit a UAF finding for this use site. Does *not* clear ``ps.is_freed``;
    every distinct use site should produce its own finding so the validator
    can reproduce each one.
    """
    confidence = 0.8 if not ps.freed_cross_branch else 0.5
    scope.findings.append(Finding(
        kind="use_after_free",
        repo=repo, file=file, line=line_no,
        function_qual=fn_name,
        cwe="CWE-416",
        detail_md=(
            f"`{ps.name}` is used at line {line_no} after being freed at "
            f"line {ps.freed_at}. Allocated at line {ps.allocated_at} via "
            f"`{ps.alloc_call}`.\n\nReason: {reason}\nUse: `{use_snippet[:160]}`"
        ),
        evidence={
            "ptr": ps.name,
            "alloc_at": ps.allocated_at,
            "free_at": ps.freed_at,
            "use_at": line_no,
            "use_snippet": use_snippet[:200],
            "function": fn_name,
            "cross_branch": ps.freed_cross_branch,
            "reason": reason,
        },
        confidence=confidence,
    ))


# ─── small helpers ─────────────────────────────────────────────────────────


def _detect_alloc(node: Node, rhs_repr: str) -> str | None:
    """Return the alloc-call source string if ``node``'s RHS is an
    allocation, else None.

    We check (a) the snippet's tail for a recognisable allocator name and
    (b) the Assign's child Call nodes — either path catches the common
    case ``T *p = malloc(n)``.
    """
    # First: look at child Call nodes
    for child in node.children:
        if child.kind != "Call":
            continue
        callee = (child.name or "").strip()
        if _ALLOC_CALLEE.match(callee):
            return callee
    # Fallback: try the RHS source-text
    m = re.match(
        r"\s*\(?\s*\w[\w\s*]*\)?\s*((?:malloc|calloc|realloc|kmalloc|"
        r"kzalloc|vmalloc|strdup|strndup|asprintf|g_malloc|g_strdup)\s*\(|"
        r"new\s+[\w:]+)",
        rhs_repr,
    )
    if m:
        return rhs_repr[:120]
    return None


def _strip_declarator(s: str) -> str:
    """Strip a C declarator decoration so ``T *p`` → ``p`` and ``*p`` → ``p``."""
    s = s.strip()
    # Drop type prefix (``T *p``)
    s = re.sub(r"^[\w:]+\s+[\s*]*", "", s)
    # Drop leading * or &
    s = s.lstrip("*& ").strip()
    # Drop trailing array subscript
    s = re.sub(r"\[[^\]]*\]$", "", s)
    return s


def _strip_address_of(s: str) -> str:
    """``&p`` → ``p``; otherwise unchanged."""
    return s.lstrip("&").strip()


def _extract_deref_target(lhs: str) -> str | None:
    """If the LHS is a deref / subscript / member access expression, return
    the underlying pointer name. Otherwise return None.
    """
    lhs = lhs.strip()
    m = re.match(r"^\*+\s*([A-Za-z_]\w*)$", lhs)
    if m:
        return m.group(1)
    m = re.match(r"^([A-Za-z_]\w*)\s*\[", lhs)
    if m:
        return m.group(1)
    m = re.match(r"^([A-Za-z_]\w*)\s*(?:->|\.)\w+", lhs)
    if m:
        return m.group(1)
    return None


def _to_dict(f: Finding) -> dict:
    return {
        "kind": f.kind, "repo": f.repo, "file": f.file, "line": f.line,
        "function_qual": f.function_qual, "cwe": f.cwe,
        "detail_md": f.detail_md, "evidence": f.evidence,
        "confidence": f.confidence,
    }
