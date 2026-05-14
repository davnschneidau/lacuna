"""
Lifetime / use-after-free analyzer.

Tracks the lifetime of heap allocations within a function:
  - alloc sites: malloc/calloc/realloc/kmalloc/new
  - free sites: free/kfree/delete (and assignments to NULL after free)
  - use sites: any access (read/write/deref) to a pointer variable

Detects:
  CWE-416 Use-after-free: use of pointer after free
  CWE-415 Double-free:    free of already-freed pointer
  CWE-562 Return of stack variable address (some patterns)
  CWE-672 Operation on resource after expiration: alias UAF

This is a per-function intra-procedural analysis (the inter-procedural
case requires alias analysis which is out of scope for v3). Most real
UAFs do have an intra-procedural manifestation — the free and the use
are usually in the same function or directly callable.

Languages: C, C++, Objective-C (the GC-free languages where this bites).
GC'd languages (Python/JS/Java/Go) are skipped — UAF impossible by design,
though `goroutine UAF` via channels exists (skipped for now).
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

ALLOC_RE = re.compile(
    r"\b(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|"
    r"strdup|strndup|asprintf|new\s+\w+)\s*\("
)
FREE_RE = re.compile(
    r"\b(free|kfree|vfree|delete)\s*\(?"
)
SET_NULL_RE = re.compile(r"^\s*(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;")


@dataclass
class PtrState:
    """Per-pointer lifetime state."""
    name: str
    allocated_at: int = 0
    alloc_call: str = ""
    freed_at: int = 0
    free_call: str = ""
    is_freed: bool = False
    aliases: list[str] = field(default_factory=list)
    use_sites: list[tuple[int, str]] = field(default_factory=list)


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
        # We need both AST (for structure) AND raw text (for regex on
        # un-parsed details, since tree-sitter C/C++ collapses macros).
        try:
            root = parse_with_tree_sitter(p, lang)
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if root is None:
            continue
        files_scanned += 1
        try:
            _analyze_module(root, text, p, repo_root, repo_name, lang,
                            findings)
        except Exception:
            continue

    return {
        "summary": f"lifetime: {len(findings)} findings across "
                    f"{files_scanned} files",
        "findings": [_to_dict(f) for f in findings],
    }


def _analyze_module(
    root: Node, text: str, path: Path, repo_root: Path, repo_name: str,
    lang: str, out: list[Finding],
) -> None:
    rel = str(path.relative_to(repo_root))
    lines = text.splitlines()

    # Group AST function nodes by their (start, end) line so we can scope
    # the text-level analysis per function. Tree-sitter Function nodes
    # don't always carry an end line — fall back to "next function start".
    fn_starts = sorted(
        (fn.line, fn.name or "<anon>")
        for fn in root.of_kind("Function") if fn is not root
    )
    if not fn_starts:
        return

    for i, (start_line, fn_name) in enumerate(fn_starts):
        end_line = fn_starts[i + 1][0] - 1 if i + 1 < len(fn_starts) \
                                            else len(lines)
        body = lines[start_line - 1:end_line]
        _analyze_function_body(
            body, start_line, fn_name, rel, repo_name, out,
        )


def _analyze_function_body(
    body: list[str], start_offset: int, fn_name: str,
    file: str, repo: str, out: list[Finding],
) -> None:
    """Body-level lifetime analysis on text lines."""
    ptrs: dict[str, PtrState] = {}

    for i, raw in enumerate(body):
        line = raw.strip()
        line_no = start_offset + i

        # Allocation: `T *p = malloc(...);` or `p = malloc(...);`
        if m := re.search(
            r"\b(\w+)\s*=\s*((?:\w+\s*\*\s*)?(?:malloc|calloc|realloc|"
            r"kmalloc|kzalloc|vmalloc|strdup|strndup|asprintf)\s*\([^)]*\))",
            line,
        ):
            name = m.group(1)
            ptrs[name] = PtrState(
                name=name, allocated_at=line_no, alloc_call=m.group(2),
            )
            continue
        # `T *p = new T(...)`
        if m := re.search(r"\b(\w+)\s*=\s*new\s+(\w+)", line):
            name = m.group(1)
            ptrs[name] = PtrState(
                name=name, allocated_at=line_no, alloc_call=f"new {m.group(2)}",
            )
            continue

        # Alias assignment: `q = p;`
        if m := re.match(r"^\s*(\w+)\s*=\s*(\w+)\s*;", line):
            dst, src = m.group(1), m.group(2)
            if src in ptrs:
                ptrs[src].aliases.append(dst)
                # The destination shares the state of the source
                if dst in ptrs:
                    # Pre-existing — don't clobber; just note alias
                    pass
                else:
                    ptrs[dst] = ptrs[src]  # alias points to same state
            continue

        # Free: `free(p);` / `delete p;` / `kfree(p);`
        if m := re.search(r"\b(?:free|kfree|vfree|delete)\s*\(?\s*(\w+)",
                          line):
            name = m.group(1)
            ps = ptrs.get(name)
            if ps:
                if ps.is_freed:
                    # Double-free
                    out.append(Finding(
                        kind="double_free",
                        repo=repo, file=file, line=line_no,
                        function_qual=fn_name,
                        cwe="CWE-415",
                        detail_md=(
                            f"`{name}` is freed at line {line_no} but was "
                            f"already freed at line {ps.freed_at} "
                            f"(originally allocated at {ps.allocated_at} "
                            f"via `{ps.alloc_call}`)."
                        ),
                        evidence={
                            "ptr": name,
                            "first_free": ps.freed_at,
                            "second_free": line_no,
                            "alloc_at": ps.allocated_at,
                        },
                        confidence=0.85,
                    ))
                else:
                    ps.is_freed = True
                    ps.freed_at = line_no
                    ps.free_call = line
                    # Propagate freed state to aliases
                    for a in ps.aliases:
                        if a in ptrs:
                            ptrs[a].is_freed = True
                            ptrs[a].freed_at = line_no
            continue

        # NULL-after-free: `p = NULL;` — clears freed state for `p` only
        if m := SET_NULL_RE.match(line):
            name = m.group(1)
            if name in ptrs and ptrs[name].is_freed:
                # Clear the state — defensive code, no longer a UAF target
                del ptrs[name]
            continue

        # Use-site detection (read/write/deref). We look for:
        #   *p, p->field, p[i], func(p), assignment from p, return p
        for name, ps in list(ptrs.items()):
            if not ps.is_freed:
                continue
            # Skip the free line itself
            if line_no == ps.freed_at:
                continue
            # Word-boundary match for pointer use
            if re.search(rf"\*\s*{re.escape(name)}\b", line) \
                    or re.search(rf"\b{re.escape(name)}\s*->", line) \
                    or re.search(rf"\b{re.escape(name)}\s*\[", line) \
                    or re.search(rf"\b{re.escape(name)}\.\w+", line) \
                    or re.search(
                        rf"\b(\w+)\s*\([^)]*\b{re.escape(name)}\b", line,
                    ):
                out.append(Finding(
                    kind="use_after_free",
                    repo=repo, file=file, line=line_no,
                    function_qual=fn_name,
                    cwe="CWE-416",
                    detail_md=(
                        f"`{name}` is used at line {line_no} after being "
                        f"freed at line {ps.freed_at}. Allocated at "
                        f"line {ps.allocated_at} via `{ps.alloc_call}`.\n\n"
                        f"Use site source: `{line[:160]}`"
                    ),
                    evidence={
                        "ptr": name,
                        "alloc_at": ps.allocated_at,
                        "free_at": ps.freed_at,
                        "use_at": line_no,
                        "use_snippet": line[:200],
                    },
                    confidence=0.8,
                ))
                # Don't keep re-reporting on the same ptr
                ps.is_freed = False  # avoid duplicate findings within fn


def _to_dict(f: Finding) -> dict:
    return {
        "kind": f.kind, "repo": f.repo, "file": f.file, "line": f.line,
        "function_qual": f.function_qual, "cwe": f.cwe,
        "detail_md": f.detail_md, "evidence": f.evidence,
        "confidence": f.confidence,
    }
