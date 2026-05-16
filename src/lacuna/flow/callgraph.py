"""
Call graph for the data-flow engine.

We build a per-repo call graph by:

1. Parsing every file into language-neutral Nodes (ast_parse).
2. Collecting every Function node into a global symbol table keyed by
   `module_dotted_name.function_name` (or just `function_name` if module
   inference fails). Functions inside classes also key as `Class.method`.
3. Walking every Function's body for Call nodes. For each Call we resolve
   the callee name to a Function in the symbol table, using:
     - exact name match (e.g. `process_input` → `mod.process_input` if unique)
     - attribute-call match (e.g. `obj.do_thing()` → `Class.do_thing` if
       only one class has `do_thing`)
     - import-aware match (e.g. `from x import y` then `y()` → `x.y`)

This is intentionally simpler than CodeQL's full type-inference, but it
catches >80% of real call sites in practice. The data-flow engine treats
unresolved calls as "external" — they don't propagate taint but they DO
record interesting sites for sanitizer/sink matching.

A reachability query is a BFS over this graph.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .ast_parse import Node, parse_python_file, parse_with_tree_sitter

SUFFIX_TO_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".java": "java", ".rb": "ruby",
}

# Skip these paths during scanning
SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/|\.min\.(js|css)$"
)


@dataclass
class FunctionInfo:
    qualname: str
    name: str
    file: str
    line: int
    language: str
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    body_node: Node | None = None
    class_name: str | None = None


@dataclass
class CallSite:
    caller_qualname: str
    callee_name: str               # raw text from source — may be qualified
    callee_resolved: str | None    # best-effort single qualname; first
                                    # candidate when multiple match
    file: str
    line: int
    args_repr: list[str] = field(default_factory=list)
    kwargs_repr: dict[str, str] = field(default_factory=dict)
    # When the call could resolve to multiple methods (e.g. ``obj.execute``
    # with several classes defining ``execute``), the taint engine fans out
    # at low confidence using this list.
    callee_candidates: list[str] = field(default_factory=list)
    ambiguous_resolution: bool = False


class CallGraph:
    """Per-repo call graph."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.functions: dict[str, FunctionInfo] = {}     # qualname → info
        self.calls_by_function: dict[str, list[CallSite]] = {}
        self.callers_of: dict[str, set[str]] = {}        # qualname → callers
        # Imports per-file: file → {local_name: full_module_path}
        self.imports_by_file: dict[str, dict[str, str]] = {}

    # ── Build ──────────────────────────────────────────────────────────────

    def build(self, max_files: int = 5000) -> None:
        files_seen = 0
        for p in self.repo_root.rglob("*"):
            if files_seen >= max_files:
                break
            if not p.is_file() or SKIP.search(str(p)):
                continue
            lang = SUFFIX_TO_LANG.get(p.suffix.lower())
            if not lang:
                continue
            files_seen += 1
            try:
                root = parse_python_file(p) if lang == "python" else parse_with_tree_sitter(p, lang)
            except Exception:
                continue
            if root is None:
                continue
            self._index_module(root, p, lang)

        # Resolution pass: now that all functions are known, resolve callees.
        for caller, calls in list(self.calls_by_function.items()):
            for cs in calls:
                candidates = self._resolve_callee_candidates(
                    cs.callee_name, cs.file,
                )
                cs.callee_candidates = candidates
                cs.ambiguous_resolution = len(candidates) > 1
                cs.callee_resolved = candidates[0] if candidates else None
                for cand in candidates:
                    self.callers_of.setdefault(cand, set()).add(caller)

    def _index_module(self, root: Node, path: Path, lang: str) -> None:
        # Build the dotted module name from pathlib parts so the result is
        # identical on Windows (backslashes) and POSIX (forward slashes). The
        # earlier ``rel_path.replace("/", ".")`` only handled POSIX and left
        # backslashes embedded in qualified names on Windows, which broke
        # cross-file callee resolution.
        rel = path.relative_to(self.repo_root).with_suffix("")
        module_name = ".".join(rel.parts)

        # First pass — imports (file-local symbol table)
        imp_map: dict[str, str] = {}
        for imp in root.of_kind("Import"):
            mod = (imp.attrs.get("module") or "")
            for n in imp.attrs.get("names", []) or []:
                local = n.split(".")[-1]
                if mod:
                    imp_map[local] = f"{mod}.{n}" if n else mod
                else:
                    imp_map[local] = n
        self.imports_by_file[str(path)] = imp_map

        # Second pass — functions (including methods)
        self._index_functions(root, module_name, lang, str(path),
                                class_name=None)

    def _index_functions(
        self, root: Node, module_name: str, lang: str, file: str,
        class_name: str | None,
    ) -> None:
        for child in root.children:
            if child.kind == "Function":
                qual_parts = [module_name]
                if class_name:
                    qual_parts.append(class_name)
                qual_parts.append(child.name or "<anon>")
                qual = ".".join(p for p in qual_parts if p)

                fi = FunctionInfo(
                    qualname=qual,
                    name=child.name or "<anon>",
                    file=file,
                    line=child.line,
                    language=lang,
                    params=child.attrs.get("params", []) or [],
                    decorators=child.attrs.get("decorators", []) or [],
                    body_node=child,
                    class_name=class_name,
                )
                self.functions[qual] = fi
                self.calls_by_function[qual] = []
                # Walk the body for Call nodes
                for call in child.of_kind("Call"):
                    if call is child:
                        continue
                    self.calls_by_function[qual].append(CallSite(
                        caller_qualname=qual,
                        callee_name=call.name or "<anon>",
                        callee_resolved=None,
                        file=call.file,
                        line=call.line,
                        args_repr=call.attrs.get("args", []) or [],
                        kwargs_repr=call.attrs.get("kwargs", {}) or {},
                    ))
                # Nested functions (Python)
                self._index_functions(child, module_name, lang, file,
                                        class_name)
            elif child.kind == "Class":
                self._index_functions(child, module_name, lang, file,
                                        class_name=child.name)
            else:
                # Top-level statements may also contain Call nodes — record
                # them as "module-level" calls under a pseudo-function
                pseudo = f"{module_name}.<module>"
                self.functions.setdefault(pseudo, FunctionInfo(
                    qualname=pseudo, name="<module>", file=file, line=1,
                    language=lang,
                ))
                self.calls_by_function.setdefault(pseudo, [])
                for call in child.of_kind("Call"):
                    self.calls_by_function[pseudo].append(CallSite(
                        caller_qualname=pseudo,
                        callee_name=call.name or "<anon>",
                        callee_resolved=None,
                        file=call.file,
                        line=call.line,
                        args_repr=call.attrs.get("args", []) or [],
                        kwargs_repr=call.attrs.get("kwargs", {}) or {},
                    ))

    # ── Resolution ─────────────────────────────────────────────────────────

    def _resolve_callee_candidates(
        self, raw_name: str, file: str,
    ) -> list[str]:
        """Return *all* qualnames that the call text could refer to.

        Earlier revisions only returned the resolution when it was unique,
        which made method-call analysis silently disappear in codebases
        where the same name appears on multiple classes. We now surface
        every candidate; consumers decide whether to fan out (taint engine
        does, at reduced confidence) or pick the first (reachability BFS).
        """
        if not raw_name:
            return []
        # Strip trailing `(...)` if tree-sitter included it
        if raw_name.endswith("()") or raw_name.endswith("(...)"):
            raw_name = raw_name.rsplit("(", 1)[0]
        # Strip ``new `` prefix (Java/C++/JS new-expression rendering)
        if raw_name.startswith("new "):
            raw_name = raw_name[4:].rstrip()

        # Direct qualname match
        if raw_name in self.functions:
            return [raw_name]

        out: list[str] = []
        seen: set[str] = set()

        def _push(q: str) -> None:
            if q in seen:
                return
            seen.add(q)
            out.append(q)

        imp_map = self.imports_by_file.get(file, {}) or {}

        # Bare name + import alias → imported qualname
        if "." not in raw_name and raw_name in imp_map:
            full = imp_map[raw_name]
            if full in self.functions:
                _push(full)
            for q in self.functions:
                if q.endswith("." + full) or q.endswith("." + raw_name):
                    _push(q)

        # Attribute call ``obj.method`` → every Class.method match
        if "." in raw_name:
            method = raw_name.rsplit(".", 1)[-1]
            for q, fi in self.functions.items():
                if fi.name == method and fi.class_name:
                    _push(q)

        # Bare name match — every function with that name
        if not out:
            for q, fi in self.functions.items():
                if fi.name == raw_name:
                    _push(q)

        return out

    def _resolve_callee(self, raw_name: str, file: str) -> str | None:
        """Legacy single-result resolver. Returns the first candidate."""
        cands = self._resolve_callee_candidates(raw_name, file)
        return cands[0] if cands else None

    # ── Reachability ──────────────────────────────────────────────────────

    def reachable_from(
        self, source: str, target: str, max_depth: int = 8,
    ) -> tuple[bool, list[str]]:
        """BFS — is target reachable from source through the call graph?

        Returns (reachable, path_qualnames). Path includes both endpoints.
        """
        if source == target:
            return True, [source]
        if source not in self.functions:
            return False, []
        visited: set[str] = set([source])
        queue: list[tuple[str, list[str]]] = [(source, [source])]
        while queue:
            cur, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for cs in self.calls_by_function.get(cur, []):
                callee = cs.callee_resolved
                if not callee:
                    continue
                if callee == target:
                    return True, [*path, callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, [*path, callee]))
        return False, []

    def callers(self, qualname: str, transitive: bool = False) -> set[str]:
        """All callers of a function. If transitive, walk the inverse graph."""
        direct = set(self.callers_of.get(qualname, set()))
        if not transitive:
            return direct
        result: set[str] = set(direct)
        frontier = set(direct)
        while frontier:
            nxt: set[str] = set()
            for f in frontier:
                for c in self.callers_of.get(f, set()):
                    if c not in result:
                        result.add(c)
                        nxt.add(c)
            frontier = nxt
        return result

    def callees(self, qualname: str, transitive: bool = False) -> set[str]:
        direct = {cs.callee_resolved for cs in self.calls_by_function.get(qualname, [])
                   if cs.callee_resolved}
        if not transitive:
            return direct
        result: set[str] = set(direct)
        frontier = set(direct)
        while frontier:
            nxt: set[str] = set()
            for f in frontier:
                for cs in self.calls_by_function.get(f, []):
                    if cs.callee_resolved and cs.callee_resolved not in result:
                        result.add(cs.callee_resolved)
                        nxt.add(cs.callee_resolved)
            frontier = nxt
        return result

    def find_functions_with_decorator(self, deco: str) -> list[FunctionInfo]:
        out: list[FunctionInfo] = []
        for fi in self.functions.values():
            for d in fi.decorators:
                if deco in d:
                    out.append(fi)
                    break
        return out
