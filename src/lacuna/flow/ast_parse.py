"""
AST abstraction for the data-flow engine.

We support two parsers:
  - Python: stdlib ``ast`` module (fastest, most accurate).
  - Other (JavaScript, TypeScript, Go, Java, Ruby, C, C++): tree-sitter via
    ``tree-sitter-language-pack`` (which has wheels for Python 3.11+).

Both adapters produce the same ``Node`` tree shape so downstream call-graph
and taint analysis work uniformly. Each materialized node carries:

  * ``kind``       — Module | Function | Class | Call | Assign | Return |
                     BinOp | If | For | While | Try | Import | Name |
                     Attribute | Constant | FString | FStringExpr
  * ``name``       — identifier text where applicable
  * ``children``   — real parent → child relationships preserved (not flat)
  * ``file``, ``line``, ``col`` — source location
  * ``attrs``      — e.g.
        ``{"args": [...], "kwargs": {...}, "op": "*",
           "rhs_repr": "...", "targets": [...], "src_snippet": "..."}``

Two design promises this module makes that earlier revisions did not:

  1. **Tree structure is preserved for tree-sitter parses too.** A function
     contains its body as children; a call contains its argument expressions
     as children; an ``If`` contains its branches' statements as children.
  2. **``BinOp`` keeps the operator.** ``_ast_dump_short`` renders the actual
     operator symbol (``*``, ``+``, ...) rather than a useless ``<op>`` token,
     so consumers (integer-overflow detection, format-string concatenation
     detection) can reason about it.
  3. **Parse errors are surfaced.** ``parse_python_file`` logs a structured
     warning when it cannot parse a file. Callers may still get ``None``
     back, but the failure is visible in logs.
"""
from __future__ import annotations

import ast as pyast
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ─── Common Node ────────────────────────────────────────────────────────────


@dataclass
class Node:
    """Language-neutral AST node."""
    kind: str
    name: str | None = None             # function/variable/class name
    children: list[Node] = field(default_factory=list)
    file: str = ""
    line: int = 0
    col: int = 0
    attrs: dict[str, Any] = field(default_factory=dict)

    def walk(self) -> Iterator[Node]:
        yield self
        for c in self.children:
            yield from c.walk()

    def of_kind(self, *kinds: str) -> Iterator[Node]:
        for n in self.walk():
            if n.kind in kinds:
                yield n


# ─── Python parser ──────────────────────────────────────────────────────────

# Map Python ast operator types to source-form strings so consumers can detect
# multiplication, concatenation, etc. Previously every BinOp collapsed to
# "<op>" which made the integer-overflow detector silently fail on Python.
_PY_BINOP = {
    "Add": "+", "Sub": "-", "Mult": "*", "Div": "/", "FloorDiv": "//",
    "Mod": "%", "Pow": "**", "LShift": "<<", "RShift": ">>",
    "BitOr": "|", "BitXor": "^", "BitAnd": "&", "MatMult": "@",
}


def parse_python_file(path: Path) -> Node | None:
    """Parse a Python file with stdlib ast. Returns a Module node or None."""
    try:
        src = path.read_text(errors="ignore")
    except OSError as e:
        logger.warning("parse_python_file: cannot read %s: %s", path, e)
        return None
    try:
        tree = pyast.parse(src, filename=str(path))
    except SyntaxError as e:
        logger.warning(
            "parse_python_file: %s: SyntaxError at line %s: %s",
            path, getattr(e, "lineno", "?"), e.msg,
        )
        return None
    root = _py_to_node(tree, str(path))
    # Attach src_snippet on control-flow / function / class / call nodes so
    # downstream heuristics (e.g. precision/integer_range bound-check
    # propagation) work uniformly with tree-sitter parses.
    _annotate_python_src_snippets(root, src.splitlines())
    return root


def _annotate_python_src_snippets(node: Node, lines: list[str]) -> None:
    if (
        node.kind in {"If", "For", "While", "Try", "Function", "Class", "Call"}
        and "src_snippet" not in node.attrs
        and 0 < node.line <= len(lines)
    ):
        # 30 lines of context is enough for the bound-check / framework
        # heuristics that read this attribute.
        end = min(node.line + 30, len(lines))
        node.attrs["src_snippet"] = "\n".join(lines[node.line - 1:end])
    for c in node.children:
        _annotate_python_src_snippets(c, lines)


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

    if isinstance(n, pyast.AugAssign):
        node = Node(
            kind="Assign", file=file, line=line, col=col,
            attrs={
                "targets": [_ast_dump_short(n.target)],
                "rhs_repr": (
                    f"{_ast_dump_short(n.target)} "
                    f"{_PY_BINOP.get(type(n.op).__name__, '<op>')}= "
                    f"{_ast_dump_short(n.value)}"
                ),
            },
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
        op_sym = _PY_BINOP.get(type(n.op).__name__, "?")
        node = Node(
            kind="BinOp", file=file, line=line, col=col,
            attrs={"op": op_sym, "op_class": type(n.op).__name__},
        )
        node.children.append(_py_to_node(n.left, file))
        node.children.append(_py_to_node(n.right, file))
        return node

    if isinstance(n, (pyast.If, pyast.For, pyast.While, pyast.Try)):
        kind = type(n).__name__
        node = Node(kind=kind, file=file, line=line, col=col)
        # Capture the test/iter expression text for bound-check propagation
        if isinstance(n, pyast.If):
            node.attrs["test_repr"] = _ast_dump_short(n.test)
        if isinstance(n, pyast.While):
            node.attrs["test_repr"] = _ast_dump_short(n.test)
        if isinstance(n, pyast.For):
            node.attrs["target_repr"] = _ast_dump_short(n.target)
            node.attrs["iter_repr"] = _ast_dump_short(n.iter)
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
    for child_ast in pyast.iter_child_nodes(n):
        node.children.append(_py_to_node(child_ast, file))
    return node


def _ast_dump_short(n: pyast.AST | None) -> str:
    """Short, human-readable rendering of a Python AST expression.

    Preserves operator symbols for BinOp so consumers can detect specific
    operators (``*`` for multiplicative-overflow analysis, ``+`` for string
    concatenation, etc.).
    """
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
        op = _PY_BINOP.get(type(n.op).__name__, "?")
        return f"{_ast_dump_short(n.left)} {op} {_ast_dump_short(n.right)}"
    if isinstance(n, pyast.UnaryOp):
        ops = {"USub": "-", "UAdd": "+", "Not": "not ", "Invert": "~"}
        return f"{ops.get(type(n.op).__name__, '?')}{_ast_dump_short(n.operand)}"
    if isinstance(n, pyast.BoolOp):
        op = "and" if isinstance(n.op, pyast.And) else "or"
        return f" {op} ".join(_ast_dump_short(v) for v in n.values)
    if isinstance(n, pyast.Compare):
        op_map = {
            "Eq": "==", "NotEq": "!=", "Lt": "<", "LtE": "<=",
            "Gt": ">", "GtE": ">=", "Is": "is", "IsNot": "is not",
            "In": "in", "NotIn": "not in",
        }
        cmp_parts: list[str] = [_ast_dump_short(n.left)]
        for op_node, comp in zip(n.ops, n.comparators, strict=False):
            cmp_parts.append(op_map.get(type(op_node).__name__, "?"))
            cmp_parts.append(_ast_dump_short(comp))
        return " ".join(cmp_parts)
    if isinstance(n, pyast.Tuple):
        return "(" + ", ".join(_ast_dump_short(e) for e in n.elts) + ")"
    if isinstance(n, pyast.List):
        return "[" + ", ".join(_ast_dump_short(e) for e in n.elts) + "]"
    if isinstance(n, pyast.Dict):
        kvs = []
        for k, v in zip(n.keys, n.values, strict=False):
            kvs.append(f"{_ast_dump_short(k)}: {_ast_dump_short(v)}")
        return "{" + ", ".join(kvs) + "}"
    if isinstance(n, pyast.Starred):
        return f"*{_ast_dump_short(n.value)}"
    if isinstance(n, pyast.IfExp):
        return (
            f"{_ast_dump_short(n.body)} if "
            f"{_ast_dump_short(n.test)} else {_ast_dump_short(n.orelse)}"
        )
    if isinstance(n, pyast.Lambda):
        return f"lambda: {_ast_dump_short(n.body)}"
    return type(n).__name__


# ─── tree-sitter parser ─────────────────────────────────────────────────────

# Map tree-sitter node types to our common Node kinds, per language.  Anything
# not present in this map falls through to the generic recursive walk so the
# tree structure is still preserved.
#
# We deliberately keep this map small but accurate. The taint engine and
# precision analyzers only need Function / Call / Assign / Return / BinOp /
# If / For / While / Try / Import.
_TS_NODE_KIND: dict[tuple[str, str], str] = {
    # JavaScript
    ("javascript", "function_declaration"): "Function",
    ("javascript", "function_expression"): "Function",
    ("javascript", "arrow_function"): "Function",
    ("javascript", "method_definition"): "Function",
    ("javascript", "class_declaration"): "Class",
    ("javascript", "call_expression"): "Call",
    ("javascript", "new_expression"): "Call",
    ("javascript", "assignment_expression"): "Assign",
    ("javascript", "variable_declarator"): "Assign",
    ("javascript", "augmented_assignment_expression"): "Assign",
    ("javascript", "return_statement"): "Return",
    ("javascript", "binary_expression"): "BinOp",
    ("javascript", "if_statement"): "If",
    ("javascript", "for_statement"): "For",
    ("javascript", "for_in_statement"): "For",
    ("javascript", "for_of_statement"): "For",
    ("javascript", "while_statement"): "While",
    ("javascript", "try_statement"): "Try",
    ("javascript", "import_statement"): "Import",
    # TypeScript reuses most of the JS grammar
    ("typescript", "function_declaration"): "Function",
    ("typescript", "function_expression"): "Function",
    ("typescript", "arrow_function"): "Function",
    ("typescript", "method_definition"): "Function",
    ("typescript", "method_signature"): "Function",
    ("typescript", "class_declaration"): "Class",
    ("typescript", "call_expression"): "Call",
    ("typescript", "new_expression"): "Call",
    ("typescript", "assignment_expression"): "Assign",
    ("typescript", "variable_declarator"): "Assign",
    ("typescript", "return_statement"): "Return",
    ("typescript", "binary_expression"): "BinOp",
    ("typescript", "if_statement"): "If",
    ("typescript", "for_statement"): "For",
    ("typescript", "while_statement"): "While",
    ("typescript", "try_statement"): "Try",
    ("typescript", "import_statement"): "Import",
    # Go
    ("go", "function_declaration"): "Function",
    ("go", "method_declaration"): "Function",
    ("go", "func_literal"): "Function",
    ("go", "type_declaration"): "Class",
    ("go", "call_expression"): "Call",
    ("go", "composite_literal"): "Call",
    ("go", "assignment_statement"): "Assign",
    ("go", "short_var_declaration"): "Assign",
    ("go", "var_declaration"): "Assign",
    ("go", "return_statement"): "Return",
    ("go", "binary_expression"): "BinOp",
    ("go", "if_statement"): "If",
    ("go", "for_statement"): "For",
    ("go", "expression_switch_statement"): "If",
    ("go", "type_switch_statement"): "If",
    ("go", "import_declaration"): "Import",
    # Java
    ("java", "method_declaration"): "Function",
    ("java", "constructor_declaration"): "Function",
    ("java", "class_declaration"): "Class",
    ("java", "interface_declaration"): "Class",
    ("java", "method_invocation"): "Call",
    ("java", "object_creation_expression"): "Call",
    ("java", "array_creation_expression"): "Call",
    ("java", "assignment_expression"): "Assign",
    ("java", "variable_declarator"): "Assign",
    ("java", "return_statement"): "Return",
    ("java", "binary_expression"): "BinOp",
    ("java", "if_statement"): "If",
    ("java", "for_statement"): "For",
    ("java", "enhanced_for_statement"): "For",
    ("java", "while_statement"): "While",
    ("java", "try_statement"): "Try",
    ("java", "import_declaration"): "Import",
    # Ruby
    ("ruby", "method"): "Function",
    ("ruby", "singleton_method"): "Function",
    ("ruby", "class"): "Class",
    ("ruby", "module"): "Class",
    ("ruby", "call"): "Call",
    ("ruby", "method_call"): "Call",
    ("ruby", "assignment"): "Assign",
    ("ruby", "operator_assignment"): "Assign",
    ("ruby", "return"): "Return",
    ("ruby", "binary"): "BinOp",
    ("ruby", "if"): "If",
    ("ruby", "unless"): "If",
    ("ruby", "for"): "For",
    ("ruby", "while"): "While",
    ("ruby", "begin"): "Try",
    # C
    ("c", "function_definition"): "Function",
    ("c", "struct_specifier"): "Class",
    ("c", "call_expression"): "Call",
    ("c", "assignment_expression"): "Assign",
    ("c", "init_declarator"): "Assign",
    ("c", "declaration"): "Assign",
    ("c", "return_statement"): "Return",
    ("c", "binary_expression"): "BinOp",
    ("c", "if_statement"): "If",
    ("c", "for_statement"): "For",
    ("c", "while_statement"): "While",
    ("c", "preproc_include"): "Import",
    # C++
    ("cpp", "function_definition"): "Function",
    ("cpp", "class_specifier"): "Class",
    ("cpp", "struct_specifier"): "Class",
    ("cpp", "call_expression"): "Call",
    ("cpp", "new_expression"): "Call",
    ("cpp", "assignment_expression"): "Assign",
    ("cpp", "init_declarator"): "Assign",
    ("cpp", "declaration"): "Assign",
    ("cpp", "return_statement"): "Return",
    ("cpp", "binary_expression"): "BinOp",
    ("cpp", "if_statement"): "If",
    ("cpp", "for_statement"): "For",
    ("cpp", "while_statement"): "While",
    ("cpp", "try_statement"): "Try",
    ("cpp", "preproc_include"): "Import",
}


def _ts_get_parser(language: str):
    """Return a (parser, language_obj) pair, or (None, None) if unavailable.

    Tries ``tree_sitter_language_pack`` first (the modern, maintained
    package). Falls back to ``tree_sitter_languages`` for backwards
    compatibility with older environments.
    """
    try:
        from tree_sitter_language_pack import get_language, get_parser
        return get_parser(language), get_language(language)
    except (ImportError, ModuleNotFoundError):
        pass
    except Exception as e:  # malformed language, missing wheel, etc.
        logger.warning("tree-sitter-language-pack failed for %s: %s",
                        language, e)
    try:
        from tree_sitter_languages import get_language, get_parser
        return get_parser(language), get_language(language)
    except (ImportError, ModuleNotFoundError):
        return None, None
    except Exception as e:
        logger.warning("tree-sitter-languages failed for %s: %s", language, e)
        return None, None


def parse_with_tree_sitter(path: Path, language: str) -> Node | None:
    """Parse a non-Python file via tree-sitter into a Node tree.

    Preserves the parent/child structure so the call graph and taint engine
    see real function bodies and call argument expressions.
    """
    parser, _lang = _ts_get_parser(language)
    if parser is None:
        return None
    try:
        src = path.read_bytes()
    except OSError as e:
        logger.warning("parse_with_tree_sitter: cannot read %s: %s", path, e)
        return None
    try:
        tree = parser.parse(src)
    except Exception as e:
        logger.warning("tree-sitter parse failed for %s: %s", path, e)
        return None

    root = _ts_to_node(tree.root_node, src, str(path), language)
    if root is None:
        # Fall back to an empty Module so callers can still iterate children.
        return Node(kind="Module", file=str(path))
    root.kind = "Module"
    root.file = str(path)
    return root


# Helper to slice the source bytes at a tree-sitter node.
def _slice(src: bytes, n) -> str:
    return src[n.start_byte:n.end_byte].decode("utf-8", errors="replace")


def _ts_to_node(ts_node, src: bytes, file: str, language: str) -> Node | None:
    """Recursive tree-sitter → Node conversion.

    Each tree-sitter node is materialized as one ``Node``; that node's
    children are the materialized representations of the tree-sitter node's
    *named* children. Anonymous tokens (punctuation, keywords) are dropped.

    For specific kinds (Function, Call, Assign, ...) we also lift commonly
    needed attributes (parameter names, call args, target names, BinOp
    operator) into ``Node.attrs`` so consumers don't have to walk children.
    """
    kind = _TS_NODE_KIND.get((language, ts_node.type))
    line = ts_node.start_point[0] + 1
    col = ts_node.start_point[1]

    if kind is None:
        # Generic recursion: materialize children but don't emit a node for
        # this anonymous wrapper. We do this so the resulting tree is shallow
        # where it doesn't carry semantic information.
        children: list[Node] = []
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                children.append(sub)
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        node = Node(
            kind=ts_node.type, file=file, line=line, col=col,
            attrs={"src_snippet": _slice(src, ts_node)[:400]},
        )
        node.children = children
        return node

    snippet = _slice(src, ts_node)[:400]
    node = Node(
        kind=kind, file=file, line=line, col=col,
        attrs={"src_snippet": snippet},
    )

    if kind == "Function":
        node.name = _ts_function_name(ts_node, src, language)
        node.attrs["params"] = _ts_function_params(ts_node, src, language)
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "Class":
        node.name = _ts_class_name(ts_node, src, language)
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "Call":
        fname, args = _ts_call_callee_and_args(ts_node, src, language)
        node.name = fname
        node.attrs["args"] = args
        node.attrs["kwargs"] = {}
        # Recurse into the *argument* subtrees so taint can walk into
        # complex expressions.
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "Assign":
        lhs, rhs = _ts_assign_lhs_rhs(ts_node, src, language)
        node.attrs["targets"] = [lhs] if lhs else []
        node.attrs["rhs_repr"] = rhs or snippet
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "Return":
        # Capture the returned expression text
        val_repr = ""
        for c in ts_node.named_children:
            val_repr = _slice(src, c)
            break
        node.attrs["value_repr"] = val_repr
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "BinOp":
        op = _ts_binop_operator(ts_node, src)
        node.attrs["op"] = op
        for c in ts_node.named_children:
            sub = _ts_to_node(c, src, file, language)
            if sub is not None:
                node.children.append(sub)
        return node

    if kind == "Import":
        # Tree-sitter import nodes vary wildly by language; just stash the
        # raw text so heuristics can grep it.
        node.attrs["names"] = []
        node.attrs["module"] = snippet
        return node

    # If / For / While / Try
    # Capture the test expression where available for bound-check propagation.
    test_child = ts_node.child_by_field_name("condition") \
        or ts_node.child_by_field_name("test")
    if test_child is not None:
        node.attrs["test_repr"] = _slice(src, test_child)
    for c in ts_node.named_children:
        sub = _ts_to_node(c, src, file, language)
        if sub is not None:
            node.children.append(sub)
    return node


# ─── tree-sitter detail helpers ─────────────────────────────────────────────


def _ts_function_name(ts_node, src: bytes, language: str) -> str | None:
    """Best-effort function-name extraction across grammars."""
    # Most grammars use field name "name"
    name_node = ts_node.child_by_field_name("name")
    if name_node is not None:
        return _slice(src, name_node)
    # Anonymous (arrow_function, func_literal) — try to find an identifier
    # in the parent variable_declarator if this is being assigned.
    return None


def _ts_function_params(ts_node, src: bytes, language: str) -> list[str]:
    params_field = ts_node.child_by_field_name("parameters") \
        or ts_node.child_by_field_name("formal_parameters")
    if params_field is None:
        return []
    out: list[str] = []
    for c in params_field.named_children:
        # The exact node type varies; grab a leading identifier.
        ident = c.child_by_field_name("name") if c.child_count else None
        if ident is None:
            out.append(_slice(src, c).strip().split()[-1].strip("(),:[]<>"))
        else:
            out.append(_slice(src, ident))
    return [p for p in out if p]


def _ts_class_name(ts_node, src: bytes, language: str) -> str | None:
    name_node = ts_node.child_by_field_name("name")
    if name_node is not None:
        return _slice(src, name_node)
    return None


def _ts_call_callee_and_args(
    ts_node, src: bytes, language: str,
) -> tuple[str | None, list[str]]:
    """Extract callee name and argument source strings from a call node."""
    callee_field = ts_node.child_by_field_name("function") \
        or ts_node.child_by_field_name("constructor") \
        or ts_node.child_by_field_name("method") \
        or ts_node.child_by_field_name("name")
    callee = _slice(src, callee_field).strip() if callee_field else None

    # Java's object_creation_expression has type field instead of function;
    # represent as "new T".
    if ts_node.type == "object_creation_expression":
        type_field = ts_node.child_by_field_name("type")
        if type_field is not None:
            callee = f"new {_slice(src, type_field).strip()}"

    if ts_node.type == "array_creation_expression":
        type_field = ts_node.child_by_field_name("type")
        if type_field is not None:
            callee = f"new {_slice(src, type_field).strip()}[]"

    # new_expression (JS/C++)
    if ts_node.type == "new_expression":
        ctor = ts_node.child_by_field_name("constructor") \
            or ts_node.child_by_field_name("type")
        if ctor is not None:
            callee = f"new {_slice(src, ctor).strip()}"

    args_field = ts_node.child_by_field_name("arguments")
    args: list[str] = []
    if args_field is not None:
        for c in args_field.named_children:
            args.append(_slice(src, c).strip())
    return callee, args


def _ts_assign_lhs_rhs(
    ts_node, src: bytes, language: str,
) -> tuple[str | None, str | None]:
    """Extract LHS target and RHS expression from an assignment node."""
    lhs_field = ts_node.child_by_field_name("left") \
        or ts_node.child_by_field_name("name") \
        or ts_node.child_by_field_name("target")
    rhs_field = ts_node.child_by_field_name("right") \
        or ts_node.child_by_field_name("value")
    lhs = _slice(src, lhs_field).strip() if lhs_field else None
    rhs = _slice(src, rhs_field).strip() if rhs_field else None
    return lhs, rhs


def _ts_binop_operator(ts_node, src: bytes) -> str:
    """Pull the operator token text out of a binary_expression."""
    # The operator is typically the (only) anonymous child between left/right
    op_field = ts_node.child_by_field_name("operator")
    if op_field is not None:
        return _slice(src, op_field).strip()
    for c in ts_node.children:
        if not c.is_named:
            text = _slice(src, c).strip()
            if text:
                return text
    return "?"
