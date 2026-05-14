"""
Taint analysis engine.

Operates on the call graph from `callgraph.py`. For each function:

1. Identify *taint introductions* — assignments whose RHS matches a source
   pattern, or parameters of HTTP handlers / queue consumers / etc.
2. Propagate taint through:
     - Direct assignment:  `x = tainted`  → x is tainted
     - Operations:  `y = tainted + "x"`  → y is tainted
     - f-strings:  `q = f"... {tainted}"`  → q is tainted
     - Concatenation, format, .format, join, etc.
     - Function-call returns:  `r = fn(tainted, ...)` — propagates if
       the callee returns a taint-tainted value (analyzed inter-procedurally)
3. Detect *sinks* — calls matching a sink pattern where any argument is
   tainted.
4. Detect *sanitizers* — calls whose return value clears taint:
     - parameterized SQL (cursor.execute with separate params)
     - urlparse + allow-list checks
     - shlex.quote, html.escape, json.dumps
     - explicit type coercion (int(), float())
5. Emit FlowPath records: source → (intermediate assignments) → sink.

This is intra- and inter-procedural up to a depth limit (default 6). It is
NOT a full abstract interpreter (no alias analysis, no points-to). But for
the vast majority of web-app data flow, this suffices to surface paths that
grep can't see.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .ast_parse import Node
from .callgraph import CallGraph, FunctionInfo


# ─── Source / sink / sanitizer catalogs ─────────────────────────────────────

# Each entry has a `kind` (canonical category) and a `pattern` (regex on the
# AST node's stringified form). We match against:
#   for sources: Assign.rhs_repr, Param name on handler functions
#   for sinks:   Call.name
#   for sanitizers: Call.name where the RETURN flows out of taint

SOURCE_PATTERNS = [
    # Python web frameworks
    ("http_request_param", re.compile(
        r"\brequest\.(args|form|json|data|files|headers|cookies|values)"
        r"(\.|\[|$)"
    )),
    ("http_request_param", re.compile(r"\bflask\.request\.")),
    ("http_request_param", re.compile(r"\brequest\.GET|\brequest\.POST")),
    ("http_request_param", re.compile(r"\brequest\.META\[")),
    ("http_request_param", re.compile(r"\bself\.request\.(query|json_body)")),
    # FastAPI
    ("http_request_param", re.compile(r"=\s*Query\(|\bQuery\(\.\.\.")),
    ("http_request_param", re.compile(r"=\s*Body\(|\bBody\(\.\.\.")),
    ("http_request_param", re.compile(r"=\s*Header\(|\bHeader\(\.\.\.")),
    # Node/Express
    ("http_request_param", re.compile(r"\breq\.(body|query|params|headers|cookies)")),
    # Go
    ("http_request_param", re.compile(
        r"\br\.URL\.Query\(\)|\br\.FormValue|\br\.PostFormValue|"
        r"\br\.Header\.Get"
    )),
    # Java Spring
    ("http_request_param", re.compile(
        r"@(RequestParam|PathVariable|RequestBody|RequestHeader)"
    )),
    # Ruby Rails
    ("http_request_param", re.compile(r"\bparams\[:|\bcookies\[:")),
    # Process environment / argv
    ("env_var", re.compile(r"\bos\.environ\b|\benviron\b|process\.env")),
    ("cli_arg", re.compile(r"\bsys\.argv|\bargv\b")),
    # File / network reads from untrusted sources
    ("file_read", re.compile(r"\bopen\([^)]+,\s*['\"]r")),
    ("queue_message", re.compile(r"\bsqs\.|\bkafka_consumer\.|\bRabbit")),
]

SINK_PATTERNS = {
    # Each entry: {kind: regex}, matched on Call.name.
    "sql_exec": re.compile(
        r"\.execute\b|\.executemany\b|\.executescript\b|"
        r"\.raw\b|\.exec_query\b|raw_query\b"
    ),
    "command_exec": re.compile(
        r"\bsubprocess\.(run|call|Popen|check_output|check_call)\b|"
        r"\bos\.system\b|\bos\.popen\b|"
        r"\bchild_process\.(exec|execSync|spawn)\b|"
        r"\bRuntime\.getRuntime\(\)\.exec\b|"
        r"\b`.+`"
    ),
    "code_eval": re.compile(r"\beval\b|\bnew Function\b|\bexec\b\s*\("),
    "deserialize": re.compile(
        r"\bpickle\.loads?\b|\bMarshal\.load\b|\bunserialize\b|"
        r"\bObjectInputStream\b|\byaml\.load\b|\bnode-serialize\b|"
        r"\bBinaryFormatter\b"
    ),
    "http_outbound": re.compile(
        r"\brequests\.(get|post|put|delete|patch|head)\b|"
        r"\baxios\.(get|post|put|delete|patch)\b|"
        r"\bhttp\.NewRequest\b|\bfetch\(|\bhttpx\.(get|post)\b|"
        r"\burlopen\b"
    ),
    "file_write": re.compile(
        r"\bopen\(.+,\s*['\"]w|\bfs\.write(File|FileSync)\b|"
        r"\bos\.rename\b|\bshutil\."
    ),
    "template_render": re.compile(
        r"\brender_template_string\b|\bTemplate\(.*\)\.render\b|"
        r"\bjinja2?\.Template\b"
    ),
    "log_with_user_input": re.compile(
        r"\blog(ger)?\.(debug|info|warn|error|critical)\b"
    ),
    "redirect": re.compile(
        r"\bredirect\b|\bres\.redirect\b|\bsend_redirect\b|\bSendRedirect\b"
    ),
}

SANITIZER_PATTERNS = {
    "parameterized_sql": re.compile(
        # match: execute("...", params) — the second arg pattern
        r"\.execute\s*\([^,)]+,\s*[\(\[]"
    ),
    "html_escape": re.compile(
        r"\bhtml\.escape\b|\bescape\b|\bmark_safe\b|\bsanitize\b"
    ),
    "shell_quote": re.compile(r"\bshlex\.quote\b|\bquote\b"),
    "url_validate": re.compile(r"\burlparse\b|\bvalidators?\.url\b"),
    "json_dump": re.compile(r"\bjson\.dumps?\b"),
    "type_coerce": re.compile(r"\bint\s*\(|\bfloat\s*\(|\bbool\s*\("),
}

HANDLER_DECORATORS = re.compile(
    r"\b(\w+\.)?(route|get|post|put|delete|patch|"
    r"GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|"
    r"app_route|handler|lambda_handler|consumer|subscribe|on_message|"
    r"task|celery_task|cron|scheduled)\b"
)


@dataclass
class TaintState:
    """Per-function taint state."""
    fn: FunctionInfo
    tainted_vars: dict[str, str] = field(default_factory=dict)
    # var → source_kind that introduced taint
    traces: dict[str, list[dict]] = field(default_factory=dict)
    # var → list of (file, line, expr) steps from introduction to current binding


@dataclass
class TaintHit:
    """A confirmed source→sink path."""
    source_kind: str
    sink_kind: str
    function: str
    file: str
    line: int
    sink_call_repr: str
    path: list[dict]                  # ordered file/line/expr steps
    sanitizers_crossed: list[str] = field(default_factory=list)
    confidence: float = 0.6


class TaintAnalyzer:
    def __init__(self, cg: CallGraph, max_depth: int = 6,
                 max_function_returns_analyzed: int = 200):
        self.cg = cg
        self.max_depth = max_depth
        # Cache of "does this function return taint when arg N is tainted?"
        self._fn_return_taint: dict[tuple[str, tuple[int, ...]], bool] = {}
        self._returns_analyzed = 0
        self._returns_cap = max_function_returns_analyzed

    # ── Entry points ────────────────────────────────────────────────────────

    def analyze(self) -> list[TaintHit]:
        """Run full analysis. Returns all taint hits found.

        Analyzes every function as a potential entry point — handlers get a
        priority pass (their params are pre-tainted), then everything else
        runs with only the internal SOURCE_PATTERNS for taint introduction.
        """
        hits: list[TaintHit] = []
        seen_func_keys: set[str] = set()
        handlers = self._handlers()
        for h in handlers:
            seen_func_keys.add(h.qualname)
            hits.extend(self._analyze_function(
                h, depth=0, tainted_params=None,
                is_handler_entrypoint=True,
            ))
        for q, fi in self.cg.functions.items():
            if q in seen_func_keys:
                continue
            hits.extend(self._analyze_function(
                fi, depth=0, tainted_params=None,
                is_handler_entrypoint=False,
            ))
        return hits

    def analyze_function_by_name(self, qualname: str) -> list[TaintHit]:
        fi = self.cg.functions.get(qualname)
        if not fi:
            return []
        return self._analyze_function(fi, depth=0, tainted_params=None)

    # ── Internals ───────────────────────────────────────────────────────────

    def _handlers(self) -> list[FunctionInfo]:
        out: list[FunctionInfo] = []
        for fi in self.cg.functions.values():
            for d in fi.decorators or []:
                if HANDLER_DECORATORS.search(d):
                    out.append(fi)
                    break
        return out

    def _analyze_function(
        self, fi: FunctionInfo, depth: int,
        tainted_params: set[str] | None,
        is_handler_entrypoint: bool = False,
    ) -> list[TaintHit]:
        if depth > self.max_depth or fi.body_node is None:
            return []
        state = TaintState(fn=fi)
        if tainted_params:
            for p in tainted_params:
                state.tainted_vars[p] = "propagated_from_caller"
                state.traces[p] = [{
                    "file": fi.file, "line": fi.line,
                    "expr": f"<parameter {p} arrives tainted>",
                }]
        if depth == 0 and is_handler_entrypoint:
            for p in fi.params:
                if p in {"self", "cls"}:
                    continue
                state.tainted_vars.setdefault(p, "handler_param")
                state.traces.setdefault(p, [{
                    "file": fi.file, "line": fi.line,
                    "expr": f"<handler parameter {p}>",
                }])

        hits: list[TaintHit] = []
        self._walk_body(fi.body_node, state, depth, hits)
        return hits

    def _walk_body(
        self, node: Node, state: TaintState, depth: int,
        hits: list[TaintHit],
    ) -> None:
        for stmt in node.children:
            self._step(stmt, state, depth, hits)

    def _step(
        self, node: Node, state: TaintState, depth: int,
        hits: list[TaintHit],
    ) -> None:
        if node.kind == "Assign":
            self._handle_assign(node, state)
        elif node.kind == "Return":
            # No-op for taint tracking within this layer; callers analyze returns
            pass
        elif node.kind == "Call":
            self._handle_call(node, state, depth, hits)
        elif node.kind in {"If", "For", "While", "Try", "Function", "Class"}:
            # Walk into bodies
            for c in node.children:
                self._step(c, state, depth, hits)
        else:
            # Default: descend into any children to surface deeper Calls
            for c in node.children:
                self._step(c, state, depth, hits)

    def _handle_assign(self, node: Node, state: TaintState) -> None:
        targets = node.attrs.get("targets", []) or []
        rhs_repr = node.attrs.get("rhs_repr", "") or ""
        # 1) Direct source match
        for kind, pat in SOURCE_PATTERNS:
            if pat.search(rhs_repr):
                for t in targets:
                    state.tainted_vars[t] = kind
                    state.traces[t] = [{
                        "file": node.file, "line": node.line,
                        "expr": f"{t} = {rhs_repr}  // source: {kind}",
                    }]
                return
        # 2) RHS references a known tainted variable
        referenced_tainted = self._referenced_tainted_vars(rhs_repr, state)
        if referenced_tainted:
            # Check if the RHS is a sanitizer call wrapping the tainted value
            if self._rhs_is_sanitized(rhs_repr):
                # Sanitized — taint cleared
                for t in targets:
                    if t in state.tainted_vars:
                        del state.tainted_vars[t]
                return
            for t in targets:
                seed = referenced_tainted[0]
                state.tainted_vars[t] = state.tainted_vars[seed]
                state.traces[t] = list(state.traces.get(seed, [])) + [{
                    "file": node.file, "line": node.line,
                    "expr": f"{t} = {rhs_repr}  // taint propagated from {seed}",
                }]
            return
        # 3) Check for taint flowing through a function call we can trace
        for child in node.children:
            if child.kind == "Call":
                callee_resolved = self._resolve_call_in_state(child, state)
                # If the callee returns taint when one of its args is tainted,
                # we propagate. This is the inter-procedural step.
                if callee_resolved:
                    tainted_arg_indices = self._arg_indices_with_taint(
                        child, state,
                    )
                    if (tainted_arg_indices and
                            self._function_returns_taint(
                                callee_resolved, tainted_arg_indices)):
                        for t in targets:
                            state.tainted_vars[t] = (
                                f"return_of_{callee_resolved}"
                            )
                            state.traces[t] = [{
                                "file": child.file, "line": child.line,
                                "expr": f"{t} = {child.name}(...) // "
                                          f"taint via return of "
                                          f"{callee_resolved}",
                            }]

    def _handle_call(
        self, node: Node, state: TaintState, depth: int,
        hits: list[TaintHit],
    ) -> None:
        # Is this call a sink?
        callee_name = node.name or ""
        for sink_kind, pat in SINK_PATTERNS.items():
            if pat.search(callee_name):
                # Check args + kwargs for tainted vars
                args = node.attrs.get("args", []) or []
                kwargs = node.attrs.get("kwargs", {}) or {}
                arg_reprs = list(args) + list(kwargs.values())
                tainted_args = []
                for ar in arg_reprs:
                    referenced = self._referenced_tainted_vars(ar, state)
                    if referenced:
                        tainted_args.extend(referenced)
                if tainted_args:
                    seed = tainted_args[0]
                    source_kind = state.tainted_vars.get(seed, "unknown")
                    # Build path
                    full_path = list(state.traces.get(seed, [])) + [{
                        "file": node.file, "line": node.line,
                        "expr": f"sink: {callee_name}(...{seed}...)",
                    }]
                    hits.append(TaintHit(
                        source_kind=source_kind,
                        sink_kind=sink_kind,
                        function=state.fn.qualname,
                        file=node.file,
                        line=node.line,
                        sink_call_repr=callee_name,
                        path=full_path,
                        sanitizers_crossed=[],
                        confidence=0.7,
                    ))
                return  # don't recurse further on a sink call

        # Otherwise descend into call args for nested Call nodes
        for c in node.children:
            self._step(c, state, depth, hits)

        # Also: if the call is to a function we can step into, propagate by
        # spawning inter-procedural analysis with the right tainted params.
        callee_resolved = self._resolve_call_in_state(node, state)
        if callee_resolved and depth < self.max_depth:
            tainted_arg_indices = self._arg_indices_with_taint(node, state)
            if tainted_arg_indices:
                callee_fn = self.cg.functions.get(callee_resolved)
                if callee_fn:
                    tainted_params = {
                        callee_fn.params[i]
                        for i in tainted_arg_indices
                        if i < len(callee_fn.params)
                    }
                    if tainted_params:
                        nested_hits = self._analyze_function(
                            callee_fn, depth + 1, tainted_params,
                        )
                        # Stitch our caller path onto each nested hit
                        for h in nested_hits:
                            h.path = (
                                [{
                                    "file": node.file, "line": node.line,
                                    "expr": (
                                        f"<call into {callee_resolved}("
                                        f"args at positions "
                                        f"{tainted_arg_indices})>"
                                    ),
                                }] + h.path
                            )
                            h.confidence = min(h.confidence, 0.6)
                            hits.append(h)

    def _referenced_tainted_vars(
        self, expr_repr: str, state: TaintState,
    ) -> list[str]:
        if not expr_repr or not state.tainted_vars:
            return []
        found = []
        for v in state.tainted_vars:
            # Word-boundary match
            if re.search(rf"\b{re.escape(v)}\b", expr_repr):
                found.append(v)
        return found

    def _rhs_is_sanitized(self, rhs: str) -> bool:
        for kind, pat in SANITIZER_PATTERNS.items():
            if pat.search(rhs):
                return True
        return False

    def _arg_indices_with_taint(
        self, call_node: Node, state: TaintState,
    ) -> list[int]:
        args = call_node.attrs.get("args", []) or []
        out: list[int] = []
        for i, a in enumerate(args):
            if self._referenced_tainted_vars(a, state):
                out.append(i)
        return out

    def _resolve_call_in_state(
        self, call_node: Node, state: TaintState,
    ) -> str | None:
        # The call graph already resolves callees during build, but per-call
        # we may have re-resolution needs. Walk the function's recorded calls
        # to find a matching site.
        for cs in self.cg.calls_by_function.get(state.fn.qualname, []):
            if cs.file == call_node.file and cs.line == call_node.line \
                    and cs.callee_resolved:
                return cs.callee_resolved
        return None

    def _function_returns_taint(
        self, qualname: str, tainted_arg_indices: list[int],
    ) -> bool:
        """Does this function return a tainted value when given tainted args?

        Heuristic: scan the function body for Return nodes whose
        value_repr references one of the tainted parameter names.
        """
        key = (qualname, tuple(sorted(tainted_arg_indices)))
        if key in self._fn_return_taint:
            return self._fn_return_taint[key]
        if self._returns_analyzed >= self._returns_cap:
            self._fn_return_taint[key] = False
            return False
        self._returns_analyzed += 1
        fi = self.cg.functions.get(qualname)
        if not fi or fi.body_node is None:
            self._fn_return_taint[key] = False
            return False
        tainted_param_names = [
            fi.params[i] for i in tainted_arg_indices if i < len(fi.params)
        ]
        if not tainted_param_names:
            self._fn_return_taint[key] = False
            return False
        for ret in fi.body_node.of_kind("Return"):
            val = ret.attrs.get("value_repr", "") or ""
            for p in tainted_param_names:
                if re.search(rf"\b{re.escape(p)}\b", val):
                    self._fn_return_taint[key] = True
                    return True
        self._fn_return_taint[key] = False
        return False
