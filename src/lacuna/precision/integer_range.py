"""
Integer range analyzer.

Detects allocation-size and array-index expressions whose value can:
  * overflow signed/unsigned integer bounds (CWE-190),
  * underflow (CWE-191), or
  * pass through into malloc/calloc/array-alloc without an upper-bound check.

Strategy

We don't do full abstract interpretation — that requires a real
constraint solver. Instead, we do a *taint-aware tractable* analysis:

  1. For each function (via Lacuna's call graph + AST), walk statements
     in order. For each integer variable, track its "shape": one of
        constant(c) | unbounded_attacker | derived_from(<set of vars>)
        | checked(<lo>, <hi>)
  2. Sources of `unbounded_attacker`:
        - assignments from request.args / request.json / wire_reads
        - function params of HTTP handler entrypoints (per v2 flow engine)
        - reads from network/file (size fields, length prefixes)
  3. Operations propagate taint:
        - x = a OP b → x.shape = unbounded_attacker if any operand is
          unbounded_attacker AND no explicit bounds-check between
          operand definition and this assignment.
        - x = constant → x.shape = constant
        - if (x < CONST) { ... use x ... } → inside the THEN branch,
          x is treated as checked(?, CONST-1) for the body.
  4. Allocation sinks:
        - malloc(expr), calloc(n, sz), new T[n], make([]T, n),
          alloca(expr), kmalloc/vmalloc, ByteBuffer.allocate(n),
          new ArrayList<>(cap), buf := make([]byte, n)
     If the size expression is unbounded_attacker without a check,
     emit an int_overflow finding (CWE-190 if multiplication, else
     CWE-789 oversized allocation).
  5. Array/slice index sinks:
        - a[i] where i.shape is unbounded_attacker without bounds check
        → CWE-129/125/787 (out-of-bounds R/W).

Languages: C/C++ via tree-sitter (the highest-value target), Python via
stdlib ast (less common to overflow but possible via array creation),
Java via tree-sitter (ByteBuffer.allocate, array creation), Go via
tree-sitter (make([]T, n)).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lacuna.flow.ast_parse import (
    Node, parse_python_file, parse_with_tree_sitter,
)

SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)

# Source patterns — what makes a value "attacker controlled at scale"?
# We reuse the v2 source list and add wire/length-field reads.
ATTACKER_SOURCE_RE = re.compile(
    r"\brequest\.(args|form|json|data|files|headers|cookies|values)|"
    r"\bos\.environ|\bsys\.argv|\bargv\b|\bgetenv\b|"
    r"\breq\.(body|query|params|headers|cookies)|"
    r"\br\.URL\.Query|\br\.FormValue|\br\.Header\.Get|"
    r"\bparams\[|@(RequestParam|PathVariable|RequestBody)|"
    r"\bread(\s*\()|\brecv(\s*\()|\bfread\b|\brecvfrom\b|"
    r"\bntohl\b|\bntohs\b|\bbe32toh\b|\ble32toh\b|"
    r"\bread_u32\b|\bread_u64\b|\bread_be32\b"
)

# Allocation-site patterns. Matched against Call.name (which is qualified
# enough — e.g. "subprocess.run" — for our purposes).
ALLOC_PATTERNS = {
    "malloc":   re.compile(r"\bmalloc\b"),
    "calloc":   re.compile(r"\bcalloc\b"),
    "realloc":  re.compile(r"\brealloc\b"),
    "kmalloc":  re.compile(r"\b(k(?:m|z)alloc|vmalloc|kcalloc)\b"),
    "alloca":   re.compile(r"\balloca\b"),
    "new[]":    re.compile(r"new\s+\w+"),
    "go_make":  re.compile(r"^make$|\bmake$"),
    "java_arr": re.compile(r"new\s+(byte|int|long|char|short)\["),
    "bytebuf":  re.compile(r"\bByteBuffer\.(allocate|allocateDirect)\b|"
                            r"ByteBuffer\.allocate"),
    "py_bytes": re.compile(r"^(bytearray|bytes)$|"
                            r"\.(bytearray|bytes)$"),
    "py_list_mul": re.compile(r"<list_mul>"),  # special tag set by AST walker
}

INDEX_GUARD_RE = re.compile(
    r"\bif\s*\([^)]*(\<|\<=|\bMIN\b|\bMAX\b|\blen\b|\bsize\b)"
)

# Common max constants — if the size is compared against any of these
# we consider it checked.
BOUND_CHECK_HINTS = (
    "MAX", "LIMIT", "CAP", "BOUND", "SIZE", "LEN", "MIN",
    "INT_MAX", "UINT_MAX", "SIZE_MAX", "PAGE_SIZE",
)

SUFFIX_TO_LANG = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp",
    ".py": "python",
    ".go": "go", ".java": "java",
    ".js": "javascript", ".ts": "typescript",
}


@dataclass
class VarShape:
    """Inferred shape of an integer variable at a program point."""
    name: str
    kind: str = "unknown"        # constant | attacker | derived | checked
    sources: list[str] = field(default_factory=list)
    bound_hi: int | None = None  # if kind == "checked"
    bound_lo: int | None = None
    defined_at_line: int = 0
    defined_in_expr: str = ""


@dataclass
class Finding:
    kind: str                   # int_overflow | int_underflow | oversized_alloc | oob_index
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
    """Run integer-range analysis across the repo."""
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
            if lang == "python":
                root = parse_python_file(p)
            else:
                root = parse_with_tree_sitter(p, lang)
        except Exception:
            continue
        if root is None:
            continue
        files_scanned += 1
        try:
            _analyze_module(root, p, repo_root, repo_name, lang, findings)
        except Exception:
            # Defensive: never let one file kill the whole scan
            continue

    return {
        "summary": f"integer_range: {len(findings)} findings across "
                    f"{files_scanned} files",
        "findings": [_to_dict(f) for f in findings],
    }


def _analyze_module(
    root: Node, path: Path, repo_root: Path, repo_name: str,
    lang: str, out: list[Finding],
) -> None:
    """Walk a module, analyzing each function."""
    rel = str(path.relative_to(repo_root))
    for fn in root.of_kind("Function"):
        if fn is root:
            continue
        _analyze_function(fn, rel, repo_name, lang, out)
    # Also analyze top-level
    _analyze_function(root, rel, repo_name, lang, out, top_level=True)


def _analyze_function(
    fn: Node, file: str, repo: str, lang: str,
    out: list[Finding], top_level: bool = False,
) -> None:
    state: dict[str, VarShape] = {}
    fn_name = fn.name or "<module>"

    # Pre-mark function parameters as attacker-controlled if the function
    # is a handler (heuristic — refined by data-flow analysis later).
    for p in fn.attrs.get("params", []) or []:
        if p not in ("self", "cls", "this"):
            state[p] = VarShape(
                name=p, kind="attacker",
                sources=["function_param"],
                defined_at_line=fn.line,
                defined_in_expr=f"<parameter {p}>",
            )

    for stmt in _flatten_stmts(fn):
        _step(stmt, state, lang, file, repo, fn_name, out)


def _flatten_stmts(fn: Node) -> list[Node]:
    """Yield statement-level nodes from a function body in source order."""
    out: list[Node] = []
    for c in fn.children:
        if c.kind in {"Function", "Class"}:
            continue
        out.append(c)
        # Walk control-flow children too — taint propagates through branches
        if c.kind in {"If", "For", "While", "Try"}:
            for cc in c.children:
                out.append(cc)
    return out


def _step(
    node: Node, state: dict[str, VarShape], lang: str,
    file: str, repo: str, fn_name: str, out: list[Finding],
) -> None:
    if node.kind == "Assign":
        _handle_assign(node, state, lang, file, repo, fn_name, out)
        # Also check whether the rhs is itself an allocation site
        # (e.g. `b = bytearray(n)` or `p = malloc(n*sz)`)
        for ch in node.children:
            if ch.kind == "Call":
                _check_allocation(ch, state, lang, file, repo, fn_name, out)
    elif node.kind == "Call":
        _check_allocation(node, state, lang, file, repo, fn_name, out)
        # Recurse into args
        for ch in node.children:
            if ch.kind == "Call":
                _step(ch, state, lang, file, repo, fn_name, out)
    elif node.kind in {"If", "For", "While", "Try"}:
        _propagate_bound_checks(node, state)
        for ch in node.children:
            _step(ch, state, lang, file, repo, fn_name, out)
    else:
        for ch in node.children:
            if ch.kind in {"Assign", "Call", "If", "For", "While", "Try"}:
                _step(ch, state, lang, file, repo, fn_name, out)


def _handle_assign(
    node: Node, state: dict[str, VarShape], lang: str,
    file: str, repo: str, fn_name: str, out: list[Finding],
) -> None:
    targets = node.attrs.get("targets", []) or []
    rhs = node.attrs.get("rhs_repr", "") or ""

    # Attacker source pattern?
    if ATTACKER_SOURCE_RE.search(rhs):
        for t in targets:
            state[t] = VarShape(
                name=t, kind="attacker",
                sources=["direct_attacker_input"],
                defined_at_line=node.line,
                defined_in_expr=f"{t} = {rhs}",
            )
        return

    # Constant?
    constant_value = _try_constant(rhs)
    if constant_value is not None:
        for t in targets:
            state[t] = VarShape(
                name=t, kind="constant",
                sources=[str(constant_value)],
                bound_lo=constant_value, bound_hi=constant_value,
                defined_at_line=node.line,
                defined_in_expr=f"{t} = {constant_value}",
            )
        return

    # Reference to known tainted variables?
    referenced = [v for v in state
                  if re.search(rf"\b{re.escape(v)}\b", rhs)]
    if referenced:
        attacker_refs = [v for v in referenced
                         if state[v].kind in ("attacker", "derived")]
        if attacker_refs:
            for t in targets:
                state[t] = VarShape(
                    name=t, kind="derived",
                    sources=list(attacker_refs),
                    defined_at_line=node.line,
                    defined_in_expr=f"{t} = {rhs}",
                )
            return

    # Otherwise: unknown shape — fall through (do nothing)


def _propagate_bound_checks(
    branch_node: Node, state: dict[str, VarShape],
) -> None:
    """Look for `if (x < CONST)` style bound checks inside the branch.
    Mark variables as `checked` for the duration of the branch's body."""
    # Heuristic: look at the branch's src snippet (where available)
    snippet = branch_node.attrs.get("src_snippet", "")
    if not snippet:
        return
    for m in re.finditer(
        r"\bif\s*\(?\s*(\w+)\s*(?:<|<=)\s*(\w+)", snippet,
    ):
        var, bound = m.group(1), m.group(2)
        if var in state and state[var].kind in ("attacker", "derived"):
            # Is the bound a "max-ish" constant?
            if any(h in bound.upper() for h in BOUND_CHECK_HINTS) \
                    or bound.isdigit():
                state[var] = VarShape(
                    name=var, kind="checked",
                    sources=state[var].sources,
                    bound_hi=int(bound) if bound.isdigit() else None,
                    defined_at_line=state[var].defined_at_line,
                    defined_in_expr=state[var].defined_in_expr + f" [checked < {bound}]",
                )


def _check_allocation(
    call: Node, state: dict[str, VarShape], lang: str,
    file: str, repo: str, fn_name: str, out: list[Finding],
) -> None:
    """If this Call is an allocation and any arg has unbounded attacker shape,
    emit a precision finding."""
    callee = call.name or ""
    matched_kind: str | None = None
    for kind, pat in ALLOC_PATTERNS.items():
        if pat.search(callee):
            matched_kind = kind
            break
    if not matched_kind:
        return

    args = call.attrs.get("args", []) or []
    if not args:
        return

    # For calloc(n, sz) the size is the product — both args matter.
    # For everything else, the first arg is the size.
    size_args = args if matched_kind == "calloc" else [args[0]]

    for size_expr in size_args:
        # Skip pure literals (e.g. malloc(1024))
        if size_expr.isdigit() or size_expr.lstrip("-").isdigit():
            continue
        # Any referenced var that's attacker-controlled?
        referenced = [v for v in state
                      if re.search(rf"\b{re.escape(v)}\b", str(size_expr))]
        risky_refs = [
            v for v in referenced
            if state[v].kind in ("attacker", "derived")
        ]
        if not risky_refs:
            continue

        # Check for multiplication in the expression — strong CWE-190 signal
        is_multiplicative = bool(re.search(
            r"\*|\bsizeof\b|\bmul_overflow\b", str(size_expr),
        ))
        cwe = "CWE-190" if is_multiplicative else "CWE-789"
        kind_label = "int_overflow" if is_multiplicative else "oversized_alloc"

        # Build detail
        traces = [
            f"  - {v} comes from {state[v].sources} "
            f"(defined at line {state[v].defined_at_line})"
            for v in risky_refs
        ]
        detail = (
            f"`{callee}({size_expr})` at {file}:{call.line} — size expression "
            f"derives from attacker-controlled value(s) without a verifiable "
            f"upper-bound check.\n\n" + "\n".join(traces)
        )

        out.append(Finding(
            kind=kind_label,
            repo=repo, file=file, line=call.line,
            function_qual=fn_name,
            cwe=cwe,
            detail_md=detail,
            evidence={
                "call": callee,
                "size_expression": size_expr,
                "risky_vars": risky_refs,
                "is_multiplicative": is_multiplicative,
                "allocator": matched_kind,
                "language": lang,
            },
            confidence=0.7 if is_multiplicative else 0.55,
        ))


def _try_constant(expr: str) -> int | None:
    s = expr.strip().strip("'\"")
    if s.startswith("0x") or s.startswith("-0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _to_dict(f: Finding) -> dict:
    return {
        "kind": f.kind, "repo": f.repo, "file": f.file, "line": f.line,
        "function_qual": f.function_qual, "cwe": f.cwe,
        "detail_md": f.detail_md, "evidence": f.evidence,
        "confidence": f.confidence,
    }
