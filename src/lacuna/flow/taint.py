"""
Taint analysis engine.

Operates on the call graph from ``callgraph.py``. For each function:

1. Identify *taint introductions* — assignments whose RHS matches a source
   pattern, or parameters of HTTP handlers / queue consumers / etc.
2. Propagate taint through:
     - Direct assignment:        ``x = tainted``
     - Operations:               ``y = tainted + "x"``
     - f-strings:                ``q = f"... {tainted}"``
     - Concatenation, format, .format, join, etc.
     - Function-call returns:    ``r = fn(tainted, ...)`` — propagates if
       the callee returns a taint-tainted value (analyzed inter-procedurally)
3. Detect *sinks* — calls matching a sink pattern where any argument is
   tainted.
4. Detect *sanitizers* — calls whose return value clears taint:
     - parameterized SQL (cursor.execute with separate params)
     - ``shlex.quote`` / ``html.escape`` / ``cgi.escape`` / ``json.dumps``
     - explicit type coercion (``int()``, ``float()``, ``bool()``)
     - allow-list URL validation (must be a *call*, not just a parse — see
       below)
5. Emit ``FlowPath`` records: source → (intermediate assignments) → sink.

Sanitizer scoping
=================

Earlier revisions treated ``urlparse(x)`` as a SSRF sanitizer. Parsing a URL
is *not* a defense — the host attribute is still attacker-controlled. We
removed that pattern and replaced it with explicit allow-list patterns
(``is_allowed_url``, ``validate_url_against_allowlist``, IPv4-rejection
helpers).

The other change: a sanitizer must apply to the *tainted subexpression*. If
the RHS is ``re.sub('x', html.escape(other), tainted)``, the ``html.escape``
call sanitizes ``other`` and not ``tainted``. We walk the RHS's child Call
nodes and only mark sanitization when the sanitizer's argument literally
references the tainted variable name.

This is intra- and inter-procedural up to a configurable depth (default 6).
It is NOT a full abstract interpreter (no alias analysis, no points-to). But
for the vast majority of web-app data flow, this catches paths that grep
can't see.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ast_parse import Node
from .callgraph import CallGraph, FunctionInfo

# ─── Source / sink / sanitizer catalogs ─────────────────────────────────────


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
    ("http_request_param", re.compile(
        r"\breq\.(body|query|params|headers|cookies)"
    )),
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
    ("queue_message", re.compile(
        r"\bsqs\.|\bkafka_consumer\.|\bRabbit|\.consume\("
    )),
]

SINK_PATTERNS = {
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

# Sanitizers are *function-call patterns*. The matcher looks at child Call
# nodes (and, as a fallback, the RHS source-text) for these patterns and
# checks that the sanitized argument is the tainted variable.
#
# Notable design decisions:
#
# * ``urlparse`` / ``urlsplit`` are NOT here. Parsing a URL does not defend
#   against SSRF; the host attribute is still attacker controlled.
# * ``html.escape`` / ``cgi.escape`` / ``shlex.quote`` require a module
#   qualifier so we don't false-positive on local functions called ``escape``
#   or ``quote``.
# * ``parameterized_sql`` is detected on the *call expression* not the
#   callee identifier — the prepared form lives in the argument string.
SANITIZER_PATTERNS = {
    "html_escape": re.compile(
        r"\b(html\.escape|cgi\.escape|markupsafe\.escape|"
        r"flask\.Markup|django\.utils\.html\.escape)\b"
    ),
    "shell_quote": re.compile(
        r"\b(shlex\.quote|pipes\.quote|shellwords\.escape|shellescape)\b"
    ),
    "url_allowlist": re.compile(
        r"\b(is_allowed_url|validate_url_against_allowlist|"
        r"assert_allowed_host|require_allowed_host|"
        r"validators?\.url|validators?\.ipv4|"
        r"ipaddress\.ip_address)\b"
    ),
    "json_dump": re.compile(
        r"\b(json\.dumps?|simplejson\.dumps?|orjson\.dumps?)\b"
    ),
    "type_coerce": re.compile(
        r"^(int|float|bool|uuid\.UUID|UUID)\s*\("
    ),
    "explicit_sanitize": re.compile(
        r"\b(bleach\.clean|sanitize_html|escape_html|"
        r"DOMPurify\.sanitize)\b"
    ),
}

# The parameterized_sql pattern is checked separately against the full call
# expression's source snippet: ``cursor.execute("SELECT ... ?", (val,))``.
PARAMETERIZED_SQL_PATTERN = re.compile(
    r"\.(execute|executemany|prepare|bind_param|query)\s*\(\s*"
    r"['\"][^'\"]*[?%]\d?[ds]?[^'\"]*['\"]\s*,",
    re.MULTILINE | re.DOTALL,
)

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
    # var → source_kind that introduced taint
    tainted_vars: dict[str, str] = field(default_factory=dict)
    # var → list of {file, line, expr} steps from introduction to current
    # binding
    traces: dict[str, list[dict]] = field(default_factory=dict)


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
        # Cache: "does this function return taint when arg N is tainted?"
        self._fn_return_taint: dict[tuple[str, tuple[int, ...]], bool] = {}
        self._returns_analyzed = 0
        self._returns_cap = max_function_returns_analyzed
        # Per-function memoization keyed on
        #   (function_qual, frozenset(tainted_param_names), depth_remaining)
        # Without this the analyzer re-walks the body of every callee at
        # every depth, blowing up on deep, recursive call graphs.
        self._fn_memo: dict[
            tuple[str, frozenset[str], int],
            list[TaintHit],
        ] = {}

    # ── Entry points ────────────────────────────────────────────────────────

    def analyze(self) -> list[TaintHit]:
        """Run full analysis. Returns all taint hits found."""
        hits: list[TaintHit] = []
        seen_func_keys: set[str] = set()
        for h in self._handlers():
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

        memo_key = (
            fi.qualname,
            frozenset(tainted_params or set()),
            self.max_depth - depth,
        )
        cached = self._fn_memo.get(memo_key)
        if cached is not None:
            return list(cached)

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
        self._fn_memo[memo_key] = list(hits)
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
        elif node.kind == "Call":
            self._handle_call(node, state, depth, hits)
        elif node.kind in {"If", "For", "While", "Try", "Function", "Class"}:
            for c in node.children:
                self._step(c, state, depth, hits)
        else:
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
            sanitized_for_vars = self._sanitized_vars_in_rhs(
                node, rhs_repr, referenced_tainted,
            )
            # Vars whose taint is *not* cleared by the RHS
            still_tainted = [
                v for v in referenced_tainted if v not in sanitized_for_vars
            ]
            if still_tainted:
                for t in targets:
                    seed = still_tainted[0]
                    state.tainted_vars[t] = state.tainted_vars[seed]
                    state.traces[t] = [*list(state.traces.get(seed, [])), {"file": node.file, "line": node.line, "expr": f"{t} = {rhs_repr}  " f"// taint propagated from {seed}"}]
            else:
                # Every referenced tainted var was sanitized in-place
                for t in targets:
                    state.tainted_vars.pop(t, None)
                    state.traces.pop(t, None)
            return

        # 3) Taint flowing through a call return (inter-procedural)
        for child in node.children:
            if child.kind != "Call":
                continue
            callee_resolved = self._resolve_call_in_state(child, state)
            if not callee_resolved:
                continue
            tainted_arg_indices = self._arg_indices_with_taint(child, state)
            if not tainted_arg_indices:
                continue
            if self._function_returns_taint(
                callee_resolved, tainted_arg_indices,
            ):
                for t in targets:
                    state.tainted_vars[t] = (
                        f"return_of_{callee_resolved}"
                    )
                    state.traces[t] = [{
                        "file": child.file, "line": child.line,
                        "expr": (
                            f"{t} = {child.name}(...) "
                            f"// taint via return of {callee_resolved}"
                        ),
                    }]

    def _handle_call(
        self, node: Node, state: TaintState, depth: int,
        hits: list[TaintHit],
    ) -> None:
        callee_name = node.name or ""
        snippet = node.attrs.get("src_snippet", "") or ""

        # Sink detection — once a call is recognized as a sink we record it
        # and bail out of further descent on this node.
        for sink_kind, pat in SINK_PATTERNS.items():
            if not pat.search(callee_name):
                continue
            args = node.attrs.get("args", []) or []
            kwargs = node.attrs.get("kwargs", {}) or {}
            arg_reprs = list(args) + list(kwargs.values())
            tainted_args: list[str] = []
            for ar in arg_reprs:
                tainted_args.extend(self._referenced_tainted_vars(ar, state))
            if not tainted_args:
                return
            seed = tainted_args[0]
            # Sinks with built-in protection (parameterized SQL): suppress
            # when the call expression itself indicates parameter binding.
            sanitizers_used = []
            if sink_kind == "sql_exec" and PARAMETERIZED_SQL_PATTERN.search(
                snippet
            ):
                sanitizers_used.append("parameterized_sql")
            source_kind = state.tainted_vars.get(seed, "unknown")
            full_path = [*list(state.traces.get(seed, [])), {"file": node.file, "line": node.line, "expr": f"sink: {callee_name}(...{seed}...)"}]
            confidence = self._score_finding(
                source_kind=source_kind,
                sink_kind=sink_kind,
                path_len=len(full_path),
                sanitizers_partial=sanitizers_used,
            )
            if "parameterized_sql" in sanitizers_used:
                # Path is documented but flagged at low confidence.
                hits.append(TaintHit(
                    source_kind=source_kind,
                    sink_kind=sink_kind,
                    function=state.fn.qualname,
                    file=node.file, line=node.line,
                    sink_call_repr=callee_name,
                    path=full_path,
                    sanitizers_crossed=sanitizers_used,
                    confidence=max(0.1, confidence - 0.4),
                ))
                return
            hits.append(TaintHit(
                source_kind=source_kind,
                sink_kind=sink_kind,
                function=state.fn.qualname,
                file=node.file, line=node.line,
                sink_call_repr=callee_name,
                path=full_path,
                sanitizers_crossed=sanitizers_used,
                confidence=confidence,
            ))
            return

        # Otherwise descend into call args for nested Call nodes
        for c in node.children:
            self._step(c, state, depth, hits)

        # Inter-procedural step: if the call resolves to a function in our
        # graph and the caller passed tainted args, analyze the callee with
        # those positions pre-tainted. Depth is incremented so the recursion
        # eventually unwinds.
        callee_resolved = self._resolve_call_in_state(node, state)
        if not callee_resolved or depth + 1 > self.max_depth:
            return
        tainted_arg_indices = self._arg_indices_with_taint(node, state)
        if not tainted_arg_indices:
            return
        callee_fn = self.cg.functions.get(callee_resolved)
        if not callee_fn:
            return
        tainted_params = {
            callee_fn.params[i]
            for i in tainted_arg_indices
            if i < len(callee_fn.params)
        }
        if not tainted_params:
            return
        nested_hits = self._analyze_function(
            callee_fn, depth + 1, tainted_params,
        )
        for h in nested_hits:
            h.path = (
                [{"file": node.file, "line": node.line, "expr": f"<call into {callee_resolved}(" f"args at positions " f"{tainted_arg_indices})>"}, *h.path]
            )
            # Each inter-procedural hop adds uncertainty.
            h.confidence = max(0.2, h.confidence - 0.05)
            hits.append(h)

    # ── Sanitizer scoping ──────────────────────────────────────────────────

    def _sanitized_vars_in_rhs(
        self, assign_node: Node, rhs_repr: str, tainted_vars_in_rhs: list[str],
    ) -> set[str]:
        """Return the subset of ``tainted_vars_in_rhs`` whose taint is cleared
        by a sanitizer call inside ``assign_node``'s RHS.

        We walk the Assign's child Call nodes and check whether each call's
        sanitizer-pattern match has the tainted variable in its argument list.
        A bare ``html.escape(other)`` does *not* sanitize ``user_input`` —
        only an explicit ``html.escape(user_input)`` does.
        """
        sanitized: set[str] = set()
        for call in self._find_calls(assign_node):
            callee = call.name or ""
            args = call.attrs.get("args", []) or []
            kwargs = call.attrs.get("kwargs", {}) or {}
            arg_reprs = [str(a) for a in args] + [
                str(v) for v in kwargs.values()
            ]
            for _kind, pat in SANITIZER_PATTERNS.items():
                if not pat.search(callee):
                    continue
                for v in tainted_vars_in_rhs:
                    if any(
                        re.search(rf"\b{re.escape(v)}\b", a)
                        for a in arg_reprs
                    ):
                        sanitized.add(v)
        return sanitized

    @staticmethod
    def _find_calls(node: Node) -> list[Node]:
        out: list[Node] = []
        for n in node.walk():
            if n.kind == "Call":
                out.append(n)
        return out

    # ── helpers ────────────────────────────────────────────────────────────

    def _referenced_tainted_vars(
        self, expr_repr: str, state: TaintState,
    ) -> list[str]:
        if not expr_repr or not state.tainted_vars:
            return []
        found = []
        for v in state.tainted_vars:
            if re.search(rf"\b{re.escape(v)}\b", expr_repr):
                found.append(v)
        return found

    def _arg_indices_with_taint(
        self, call_node: Node, state: TaintState,
    ) -> list[int]:
        args = call_node.attrs.get("args", []) or []
        out: list[int] = []
        for i, a in enumerate(args):
            if self._referenced_tainted_vars(str(a), state):
                out.append(i)
        return out

    def _resolve_call_in_state(
        self, call_node: Node, state: TaintState,
    ) -> str | None:
        for cs in self.cg.calls_by_function.get(state.fn.qualname, []):
            if (
                cs.file == call_node.file
                and cs.line == call_node.line
                and cs.callee_resolved
            ):
                return cs.callee_resolved
        return None

    def _function_returns_taint(
        self, qualname: str, tainted_arg_indices: list[int],
    ) -> bool:
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

    # ── confidence ─────────────────────────────────────────────────────────

    @staticmethod
    def _score_finding(
        source_kind: str, sink_kind: str, path_len: int,
        sanitizers_partial: list[str],
    ) -> float:
        """Heuristic confidence score in ``[0.2, 0.95]``.

        Earlier revisions hardcoded ``0.7`` for direct hits and ``0.6``
        across inter-procedural hops. That gave noisy reports that the
        validator couldn't prioritize. The new function rewards:

          * direct, specific sources (``http_request_param``, ``cli_arg``);
          * specific sinks (``sql_exec``, ``command_exec``, ``code_eval``);
          * short paths (fewer hops means less heuristic uncertainty);

        and penalises:

          * generic / synthetic sources (``unknown``, ``propagated_from_caller``);
          * the presence of *partial* mitigations like ``parameterized_sql``
            (we still report; the validator decides).
        """
        score = 0.55
        if source_kind in {"http_request_param", "cli_arg"}:
            score += 0.20
        elif source_kind in {"env_var", "queue_message"}:
            score += 0.10
        elif source_kind in {"unknown", "propagated_from_caller"}:
            score -= 0.10
        if sink_kind in {"command_exec", "code_eval", "deserialize"}:
            score += 0.15
        elif sink_kind in {"sql_exec", "template_render", "redirect"}:
            score += 0.10
        elif sink_kind in {"log_with_user_input"}:
            score -= 0.05
        if path_len <= 2:
            score += 0.05
        elif path_len > 6:
            score -= 0.05
        if sanitizers_partial:
            score -= 0.15
        return round(max(0.2, min(0.95, score)), 3)
