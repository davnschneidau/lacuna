"""
Tests for Lacuna's custom inter-procedural data-flow engine.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

# The taint engine parses Python out of the stdlib ``ast`` module, so the
# baseline tests don't need any third-party language parser. For the
# non-Python tests we'd guard with ``pytest.importorskip``.
from lacuna.flow import (
    build_call_graph,
    callers,
    reachable,
    taint_paths,
)


@pytest.fixture
def flask_app(tmp_path: Path) -> Path:
    """A minimal Flask app with three handlers: vulnerable, sanitized, direct."""
    (tmp_path / "app.py").write_text(textwrap.dedent("""
        from flask import Flask, request
        import subprocess, sqlite3, html

        app = Flask(__name__)
        conn = sqlite3.connect("app.db")

        def normalize(name):
            return name.strip()

        def sanitize(s):
            return html.escape(s)

        @app.route("/search")
        def search():
            q = request.args.get("q")
            nq = normalize(q)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM items WHERE name = '{nq}'")
            return "ok"

        @app.route("/safe")
        def safe_endpoint():
            q = request.args.get("q")
            nq = sanitize(q)
            return f"<div>{nq}</div>"

        @app.route("/run")
        def run_cmd():
            cmd = request.args.get("cmd")
            subprocess.run(cmd, shell=True)
            return "done"
    """).strip())
    return tmp_path


def test_call_graph_indexes_all_functions(flask_app):
    cg = build_call_graph(flask_app)
    qualnames = set(cg.functions.keys())
    assert "app.search" in qualnames
    assert "app.run_cmd" in qualnames
    assert "app.safe_endpoint" in qualnames
    assert "app.normalize" in qualnames
    assert "app.sanitize" in qualnames


def test_call_graph_resolves_local_calls(flask_app):
    cg = build_call_graph(flask_app)
    calls_from_search = [
        cs.callee_resolved
        for cs in cg.calls_by_function.get("app.search", [])
        if cs.callee_resolved
    ]
    assert "app.normalize" in calls_from_search


def test_reachability_finds_path(flask_app):
    cg = build_call_graph(flask_app)
    ok, path = reachable(cg, "app.search", "app.normalize")
    assert ok is True
    assert path[0] == "app.search"
    assert "app.normalize" in path


def test_reachability_false_for_unrelated_functions(flask_app):
    cg = build_call_graph(flask_app)
    ok, _ = reachable(cg, "app.normalize", "app.sanitize")
    assert ok is False


def test_callers_finds_handler(flask_app):
    cg = build_call_graph(flask_app)
    cs = callers(cg, "app.normalize", transitive=False)
    assert "app.search" in cs


def test_taint_engine_finds_sqli_through_intermediate_function(flask_app):
    """The classic: request.args → normalize() → cursor.execute(f-string).
    Cross-function taint with f-string injection."""
    cg = build_call_graph(flask_app)
    hits = taint_paths(cg)
    sql_hits = [h for h in hits if h.sink_kind == "sql_exec"]
    assert len(sql_hits) >= 1
    h = sql_hits[0]
    assert h.source_kind == "http_request_param"
    assert "search" in h.function
    # The path must show the intermediate normalize() call
    path_exprs = " ".join(s.get("expr", "") for s in h.path)
    assert "normalize" in path_exprs


def test_taint_engine_finds_direct_command_injection(flask_app):
    cg = build_call_graph(flask_app)
    hits = taint_paths(cg)
    cmd_hits = [h for h in hits if h.sink_kind == "command_exec"]
    assert len(cmd_hits) >= 1
    assert cmd_hits[0].source_kind == "http_request_param"
    assert "run_cmd" in cmd_hits[0].function


def test_taint_engine_respects_sanitizers(tmp_path):
    """A real sanitizer on the safe path must suppress an otherwise identical
    sink. We give the safe endpoint the *same* sink (cursor.execute on an
    f-string) as the vulnerable one — the only difference is that the safe
    path passes the param through ``html.escape``. If the sanitizer logic
    is correct, the vulnerable endpoint produces a hit and the safe one
    does not."""
    (tmp_path / "app.py").write_text(textwrap.dedent("""
        from flask import Flask, request
        import sqlite3, html

        app = Flask(__name__)
        conn = sqlite3.connect("app.db")

        @app.route("/vuln")
        def vuln():
            q = request.args.get("q")
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM items WHERE name = '{q}'")
            return "ok"

        @app.route("/safe")
        def safe_endpoint():
            q = request.args.get("q")
            nq = html.escape(q)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM items WHERE name = '{nq}'")
            return "ok"
    """).strip())
    cg = build_call_graph(tmp_path)
    hits = taint_paths(cg)
    sql_hits = [h for h in hits if h.sink_kind == "sql_exec"]
    vuln_hits = [h for h in sql_hits if "vuln" in h.function]
    safe_hits = [h for h in sql_hits if "safe_endpoint" in h.function]
    assert len(vuln_hits) >= 1, "vuln endpoint should produce at least one SQLi hit"
    assert len(safe_hits) == 0, (
        "html.escape on the safe path should suppress the SQLi hit; "
        f"got {len(safe_hits)} hits"
    )


def test_taint_engine_inter_procedural_recursion_limit(tmp_path):
    """Construct a chain longer than max_depth and confirm it stops.

    The chain ends at a real ``cursor.execute(f"...{x}...")`` sink so the
    test actually exercises depth-limited propagation rather than just
    proving the engine doesn't crash."""
    (tmp_path / "deep.py").write_text(textwrap.dedent("""
        from flask import Flask, request
        import sqlite3
        app = Flask(__name__)
        conn = sqlite3.connect("d.db")

        def a(x): return b(x)
        def b(x): return c(x)
        def c(x): return d(x)
        def d(x): return e(x)
        def e(x): return f(x)
        def f(x): return g(x)
        def g(x): return h(x)
        def h(x):
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM t WHERE n = '{x}'")
            return x

        @app.route("/x")
        def handler():
            q = request.args.get("q")
            return a(q)
    """).strip())
    cg = build_call_graph(tmp_path)
    shallow = taint_paths(cg, max_depth=3)
    deep = taint_paths(cg, max_depth=12)

    shallow_sqli = [h for h in shallow if h.sink_kind == "sql_exec"]
    deep_sqli = [h for h in deep if h.sink_kind == "sql_exec"]
    assert len(shallow_sqli) == 0, (
        "max_depth=3 must not reach a sink 7 hops away; "
        f"got {len(shallow_sqli)} hits"
    )
    assert len(deep_sqli) >= 1, (
        "max_depth=12 should reach the sink at the bottom of the 7-hop "
        f"chain; got {len(deep_sqli)} hits"
    )
    # ...and the path must actually traverse the handler entrypoint, not
    # be a spurious hit on the helpers in isolation.
    chained = [
        h for h in deep_sqli
        if any("call into" in (step.get("expr", "") or "") for step in h.path)
    ]
    assert chained, (
        "the deep hit must show inter-procedural hops in its path; "
        f"got paths={[h.path for h in deep_sqli]}"
    )


def test_python_specific_constructs(tmp_path):
    """f-string interpolation must propagate taint into a downstream
    ``render_template_string`` call. This is the bread-and-butter Flask
    XSS shape; if it doesn't fire there's no point shipping the engine.
    """
    (tmp_path / "weird.py").write_text(textwrap.dedent("""
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.route("/fstr")
        def handler():
            name = request.args.get("name")
            body = f"<h1>Hello {name}</h1>"
            return render_template_string(body)
    """).strip())
    cg = build_call_graph(tmp_path)
    hits = taint_paths(cg)
    template_hits = [
        h for h in hits if h.sink_kind == "template_render" and "handler" in h.function
    ]
    assert len(template_hits) >= 1, (
        "attacker-controlled f-string flowing into render_template_string "
        f"must register; got hits={[(h.function, h.sink_kind) for h in hits]}"
    )
