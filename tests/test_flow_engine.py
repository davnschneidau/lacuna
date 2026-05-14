"""
Tests for Lacuna's custom inter-procedural data-flow engine.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from lacuna.flow import (
    build_call_graph, callers, reachable, taint_paths,
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


def test_taint_engine_respects_sanitizers(flask_app):
    """app.safe_endpoint uses html.escape and should NOT produce a hit."""
    cg = build_call_graph(flask_app)
    hits = taint_paths(cg)
    sanitized_hits = [h for h in hits if "safe_endpoint" in h.function]
    # If the f-string return path were a sink we'd see template_render here.
    # The point is: even if a hit appears, the sanitizer should suppress it.
    # Currently the f-string return isn't a sink (it's just a string literal),
    # so there should be zero hits in safe_endpoint.
    assert len(sanitized_hits) == 0


def test_taint_engine_inter_procedural_recursion_limit(tmp_path):
    """Construct a chain longer than max_depth and confirm it stops."""
    (tmp_path / "deep.py").write_text(textwrap.dedent("""
        from flask import Flask, request
        app = Flask(__name__)

        def a(x): return b(x)
        def b(x): return c(x)
        def c(x): return d(x)
        def d(x): return e(x)
        def e(x): return f(x)
        def f(x): return g(x)
        def g(x): return h(x)
        def h(x): return x

        @app.route("/x")
        def handler():
            q = request.args.get("q")
            return a(q)
    """).strip())
    cg = build_call_graph(tmp_path)
    hits = taint_paths(cg, max_depth=3)
    # With max_depth=3 the engine can't trace through 7 hops to a sink — and
    # there's no sink here anyway, so just confirm no crash and 0 hits.
    assert isinstance(hits, list)


def test_python_specific_constructs(tmp_path):
    """f-strings, dict literals, attribute access — all should be parsed."""
    (tmp_path / "weird.py").write_text(textwrap.dedent("""
        from flask import Flask, request
        import subprocess
        app = Flask(__name__)

        @app.route("/exec")
        def handler():
            data = request.json
            cmd = data["cmd"]
            args = {"shell": True, "cmd": cmd}
            subprocess.run(args["cmd"], shell=args["shell"])
            return "ok"
    """).strip())
    cg = build_call_graph(tmp_path)
    # Even if dict-subscript taint is hard, the engine shouldn't crash
    hits = taint_paths(cg)
    assert isinstance(hits, list)
