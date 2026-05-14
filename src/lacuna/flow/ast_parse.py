"""
AST abstraction for the data-flow engine.

We support two parsers:
  - Python: stdlib `ast` module — fastest and most accurate.
  - Other (JS/TS/Go/Java/Ruby): tree-sitter via tree-sitter-languages.

The Node type below is the *common* shape we operate on. Each language adapter
populates it with the same semantic kinds so the downstream call graph and
taint analysis work uniformly.

Semantic kinds we extract:
  Module, Function, Class, Call, Assign, Return, Param, Name, Attribute,
  String, Number, BinOp, If, For, While, Try, Import.
"""
from __future__ import annotations

import ast as pyast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


@dataclass
class Node:
    """Language-neutral AST node."""
    kind: str
    name: str | None = None             # function/variable/class name
    children: list["Node"] = field(default_factory=list)
    # Source location
    file: str = ""
    line: int = 0
    col: int = 0
    # Free-form annotations populated per-language
    attrs: dict[str, Any] = field(default_factory=dict)

    def walk(self) -> Iterator["Node"]:
        yield self
        for c in self.children:
            yield from c.walk()

    def of_kind(self, *kinds: str) -> Iterator["Node"]:
        for n in self.walk():
            if n.kind in kinds:
                yield n


# ─── Python parser ──────────────────────────────────────────────────────────

def parse_python_file(path: Path) -> Node | None:
    """Parse a Python file with stdlib ast. Returns a Module node or None."""
    try:
        src = path.read_text(errors="ignore")
        tree = pyast.parse(src, filename=str(path))
    except (SyntaxError, OSError):
        return None
    return _py_to_node(tree, str(path))


def _py_to_node(n: pyast.AST, file: str) -> Node:
    line = getattr(n, "lineno", 0) or 0
    col = getattr(n, "col_offset", 0) or 0

    if isinstance(n, pyast.Module):
        node = Node(kind="Module", file=file)
        for c in n.body:
            node.children.append(_py_to_node(c, file))
        return node

    if isinstance(n, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
        params = [a.arg for a in n.args.args]
        node = Node(
            kind="Function", name=n.name, file=file, line=line, col=col,
            attrs={"params": params, "decorators": [
                _ast_dump_short(d) for d in n.decorator_list]},
        )
        for c in n.body:
            node.children.append(_py_to_node(c, file))
        return node

    if isinstance(n, pyast.ClassDef):
        node = Node(
            kind="Class", name=n.name, file=file, line=line, col=col,
            attrs={"bases": [_ast_dump_short(b) for b in n.bases]},
        )
        for c in n.body:
            node.children.append(_py_to_node(c, file))
        return node

    if isinstance(n, pyast.Call):
        func_repr = _ast_dump_short(n.func)
        node = Node(
            kind="Call", name=func_repr, file=file, line=line, col=col,
            attrs={
                "args": [_ast_dump_short(a) for a in n.args],
                "kwargs": {k.arg: _ast_dump_short(k.value)
                            for k in n.keywords if k.arg},
            },
        )
        # children include argument expressions so def-use can recurse
        for a in n.args:
            node.children.append(_py_to_node(a, file))
        for kw in n.keywords:
            node.children.append(_py_to_node(kw.value, file))
        return node

    if isinstance(n, pyast.Assign):
        targets = [_ast_dump_short(t) for t in n.targets]
        node = Node(
            kind="Assign", file=file, line=line, col=col,
            attrs={"targets": targets, "rhs_repr": _ast_dump_short(n.value)},
        )
        node.children.append(_py_to_node(n.value, file))
        return node

    if isinstance(n, pyast.AnnAssign) and n.value is not None:
        node = Node(
            kind="Assign", file=file, line=line, col=col,
            attrs={"targets": [_ast_dump_short(n.target)],
                    "rhs_repr": _ast_dump_short(n.value)},
        )
        node.children.append(_py_to_node(n.value, file))
        return node

    if isinstance(n, pyast.Return) and n.value is not None:
        node = Node(
            kind="Return", file=file, line=line, col=col,
            attrs={"value_repr": _ast_dump_short(n.value)},
        )
        node.children.append(_py_to_node(n.value, file))
        return node

    if isinstance(n, pyast.Name):
        return Node(kind="Name", name=n.id, file=file, line=line, col=col)

    if isinstance(n, pyast.Attribute):
        return Node(
            kind="Attribute", name=_ast_dump_short(n), file=file,
            line=line, col=col,
        )

    if isinstance(n, pyast.Constant):
        return Node(
            kind="Constant", name=type(n.value).__name__, file=file,
            line=line, col=col,
            attrs={"value": repr(n.value)[:120]},
        )

    if isinstance(n, pyast.JoinedStr):  # f-string
        node = Node(kind="FString", file=file, line=line, col=col)
        for v in n.values:
            node.children.append(_py_to_node(v, file))
        return node

    if isinstance(n, pyast.FormattedValue):
        node = Node(kind="FStringExpr", file=file, line=line, col=col,
                     attrs={"expr_repr": _ast_dump_short(n.value)})
        node.children.append(_py_to_node(n.value, file))
        return node

    if isinstance(n, pyast.BinOp):
        node = Node(
            kind="BinOp", file=file, line=line, col=col,
            attrs={"op": type(n.op).__name__},
        )
        node.children.append(_py_to_node(n.left, file))
        node.children.append(_py_to_node(n.right, file))
        return node

    if isinstance(n, (pyast.If, pyast.For, pyast.While, pyast.Try)):
        kind = type(n).__name__
        node = Node(kind=kind, file=file, line=line, col=col)
        # Children: body + orelse + (try) handlers + finalbody
        for c in getattr(n, "body", []) or []:
            node.children.append(_py_to_node(c, file))
        for c in getattr(n, "orelse", []) or []:
            node.children.append(_py_to_node(c, file))
        for h in getattr(n, "handlers", []) or []:
            for c in h.body:
                node.children.append(_py_to_node(c, file))
        for c in getattr(n, "finalbody", []) or []:
            node.children.append(_py_to_node(c, file))
        return node

    if isinstance(n, (pyast.Import, pyast.ImportFrom)):
        names = [a.name for a in n.names]
        module = getattr(n, "module", None)
        return Node(
            kind="Import", file=file, line=line, col=col,
            attrs={"names": names, "module": module},
        )

    if isinstance(n, pyast.Expr):
        return _py_to_node(n.value, file)

    # Fallback — wrap as Unknown so the children walker still descends
    node = Node(kind=type(n).__name__, file=file, line=line, col=col)
    for c in pyast.iter_child_nodes(n):
        node.children.append(_py_to_node(c, file))
    return node


def _ast_dump_short(n: pyast.AST | None) -> str:
    if n is None:
        return ""
    if isinstance(n, pyast.Name):
        return n.id
    if isinstance(n, pyast.Constant):
        return repr(n.value)[:80]
    if isinstance(n, pyast.Attribute):
        return f"{_ast_dump_short(n.value)}.{n.attr}"
    if isinstance(n, pyast.Call):
        args = ", ".join(_ast_dump_short(a) for a in n.args)
        return f"{_ast_dump_short(n.func)}({args})"
    if isinstance(n, pyast.Subscript):
        return f"{_ast_dump_short(n.value)}[{_ast_dump_short(n.slice)}]"
    if isinstance(n, pyast.JoinedStr):
        # Expand variables so taint analysis can see them
        parts = []
        for v in n.values:
            if isinstance(v, pyast.FormattedValue):
                parts.append(f"{{{_ast_dump_short(v.value)}}}")
            elif isinstance(v, pyast.Constant):
                parts.append(str(v.value)[:40])
            else:
                parts.append(_ast_dump_short(v))
        return "f'" + "".join(parts) + "'"
    if isinstance(n, pyast.FormattedValue):
        return f"{{{_ast_dump_short(n.value)}}}"
    if isinstance(n, pyast.BinOp):
        return f"{_ast_dump_short(n.left)} <op> {_ast_dump_short(n.right)}"
    if isinstance(n, pyast.Tuple):
        return "(" + ", ".join(_ast_dump_short(e) for e in n.elts) + ")"
    if isinstance(n, pyast.List):
        return "[" + ", ".join(_ast_dump_short(e) for e in n.elts) + "]"
    if isinstance(n, pyast.Dict):
        kvs = []
        for k, v in zip(n.keys, n.values):
            kvs.append(f"{_ast_dump_short(k)}: {_ast_dump_short(v)}")
        return "{" + ", ".join(kvs) + "}"
    if isinstance(n, pyast.Starred):
        return f"*{_ast_dump_short(n.value)}"
    return type(n).__name__


# ─── tree-sitter parser (JS/TS/Go/Java/Ruby) ────────────────────────────────

# Tree-sitter capture queries normalized to the common kind vocabulary.
# Each language has a single query that fires on the constructs we care about.
TS_QUERIES = {
    "javascript": r"""
        (function_declaration name: (identifier) @function.name) @function
        (arrow_function) @arrow
        (call_expression function: [(identifier) (member_expression)] @call.func) @call
        (assignment_expression left: (_) @assign.lhs right: (_) @assign.rhs) @assign
        (variable_declarator name: (identifier) @assign.lhs value: (_)? @assign.rhs) @var
        (return_statement (_)? @ret.value) @return
        (identifier) @name
    """,
    "typescript": r"""
        (function_declaration name: (identifier) @function.name) @function
        (call_expression function: [(identifier) (member_expression)] @call.func) @call
        (variable_declarator name: (identifier) @assign.lhs value: (_)? @assign.rhs) @var
        (return_statement (_)? @ret.value) @return
        (identifier) @name
    """,
    "go": r"""
        (function_declaration name: (identifier) @function.name) @function
        (call_expression function: (_) @call.func) @call
        (assignment_statement left: (_) @assign.lhs right: (_) @assign.rhs) @assign
        (short_var_declaration left: (_) @assign.lhs right: (_) @assign.rhs) @short_var
        (return_statement) @return
    """,
    "java": r"""
        (method_declaration name: (identifier) @function.name) @function
        (method_invocation name: (identifier) @call.func) @call
        (return_statement) @return
    """,
    "ruby": r"""
        (method name: (identifier) @function.name) @function
        (call method: (identifier) @call.func) @call
        (return) @return
    """,
}


def parse_with_tree_sitter(path: Path, language: str) -> Node | None:
    """Parse non-Python files via tree-sitter. Returns Module-like Node."""
    try:
        from tree_sitter_languages import get_language, get_parser
    except ImportError:
        return None
    try:
        parser = get_parser(language)
        lang = get_language(language)
    except Exception:
        return None
    try:
        src = path.read_bytes()
    except OSError:
        return None

    tree = parser.parse(src)
    root = Node(kind="Module", file=str(path))
    query_str = TS_QUERIES.get(language)
    if not query_str:
        return root
    try:
        q = lang.query(query_str)
    except Exception:
        return root

    # Group captures by their parent node so we materialize Function/Call/Assign nodes
    captures = q.captures(tree.root_node)
    materialized: list[Node] = []
    for ts_node, cap_name in captures:
        if cap_name.endswith(".name") or cap_name.endswith(".func") \
                or cap_name.endswith(".lhs") or cap_name.endswith(".rhs") \
                or cap_name.endswith(".value"):
            continue  # these are children of the parent capture; folded below
        line = ts_node.start_point[0] + 1
        col = ts_node.start_point[1]
        text = src[ts_node.start_byte:ts_node.end_byte].decode(errors="replace")[:200]
        if cap_name == "function":
            # Find the inner @function.name capture
            name = None
            for child_node, child_cap in captures:
                if child_cap == "function.name" and \
                        ts_node.start_byte <= child_node.start_byte \
                        and child_node.end_byte <= ts_node.end_byte:
                    name = src[child_node.start_byte:child_node.end_byte] \
                        .decode(errors="replace")
                    break
            materialized.append(Node(
                kind="Function", name=name, file=str(path),
                line=line, col=col, attrs={"src_snippet": text},
            ))
        elif cap_name in ("call",):
            fname = None
            args: list[str] = []
            for child_node, child_cap in captures:
                if child_cap == "call.func" and \
                        ts_node.start_byte <= child_node.start_byte \
                        and child_node.end_byte <= ts_node.end_byte:
                    fname = src[child_node.start_byte:child_node.end_byte] \
                        .decode(errors="replace")
                    break
            materialized.append(Node(
                kind="Call", name=fname, file=str(path), line=line, col=col,
                attrs={"src_snippet": text, "args": args},
            ))
        elif cap_name in ("assign", "var", "short_var"):
            lhs = None
            rhs = None
            for child_node, child_cap in captures:
                if not (ts_node.start_byte <= child_node.start_byte
                         and child_node.end_byte <= ts_node.end_byte):
                    continue
                if child_cap == "assign.lhs":
                    lhs = src[child_node.start_byte:child_node.end_byte] \
                        .decode(errors="replace")
                if child_cap == "assign.rhs":
                    rhs = src[child_node.start_byte:child_node.end_byte] \
                        .decode(errors="replace")
            materialized.append(Node(
                kind="Assign", file=str(path), line=line, col=col,
                attrs={"targets": [lhs] if lhs else [],
                        "rhs_repr": rhs or text},
            ))
        elif cap_name == "return":
            materialized.append(Node(
                kind="Return", file=str(path), line=line, col=col,
                attrs={"src_snippet": text},
            ))

    # Place all materialized nodes under the module's children (flat). The
    # call graph builder works function-by-function and can re-cluster.
    root.children = materialized
    return root
