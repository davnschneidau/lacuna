"""Smoke tests for the lacuna-recon MCP server tool surface.

We instantiate the server against a tiny synthetic repo and assert that
data-flow-style tools produce *categorized* output rather than the
collapsed 'all-in-one-bucket' shape the pre-3.0 server returned.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

pytest.importorskip("mcp")


def _build_workspace(tmp_path: Path) -> Path:
    """Create a workspace with one tiny Python repo and a manifest."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    repo = workspace / "tiny"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\n"
        "import sqlite3\n"
        "app = Flask(__name__)\n"
        "conn = sqlite3.connect('db.sqlite')\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    q = request.args.get('q')\n"
        "    conn.cursor().execute(f\"SELECT * FROM t WHERE n='{q}'\")\n"
        "    return 'ok'\n"
    )
    manifest = workspace / "app.lacuna.yaml"
    manifest.write_text(yaml.safe_dump({
        "application": {"name": "tiny-app"},
        "repos": [{"name": "tiny", "source": "local"}],
    }))
    return workspace


def _read_json(response) -> dict:
    """Decode the single TextContent payload back into a dict."""
    assert len(response) == 1
    return json.loads(response[0].text)


def _setup_env(monkeypatch, workspace: Path) -> None:
    monkeypatch.setenv("LACUNA_WORKSPACE", str(workspace))
    monkeypatch.setenv("LACUNA_MANIFEST_RESOLVED", str(workspace / "app.lacuna.yaml"))
    monkeypatch.setenv("LACUNA_TOOL_CACHE_DIR", str(workspace / ".cache"))
    monkeypatch.setenv("LACUNA_EVIDENCE_DIR", str(workspace / ".evidence"))


def test_app_inventory_lists_repos_from_manifest(tmp_path, monkeypatch):
    ws = _build_workspace(tmp_path)
    _setup_env(monkeypatch, ws)
    # Re-import to pick up env vars cleanly.
    import importlib

    from lacuna.tools import recon_server
    importlib.reload(recon_server)
    out = _read_json(recon_server._tool_app_inventory())
    assert any(r["name"] == "tiny" for r in out["handles"])


def test_data_sources_categorizes_by_label(tmp_path, monkeypatch):
    """Phase 3 fix: ``data_sources`` must group hits by *category* labels
    (``source:http_request``, ``source:env`` …) rather than by language."""
    ws = _build_workspace(tmp_path)
    _setup_env(monkeypatch, ws)
    import importlib

    from lacuna.tools import recon_server
    importlib.reload(recon_server)
    out = _read_json(recon_server._tool_data_sources({"repo": "tiny"}))
    facets = out.get("facets", {})
    by_category = (facets.get("by_category")
                   or facets.get("counts")
                   or {})
    has_category_keys = any(
        str(k).startswith("source:") for k in by_category
    )
    has_handles_with_category = any(
        h.get("category", "").startswith("source:")
        for h in out.get("handles", [])
    )
    assert has_category_keys or has_handles_with_category, (
        f"data_sources must use 'source:*' category labels; "
        f"facets={facets}, handles={out.get('handles')}"
    )


def test_data_sinks_categorizes_by_label(tmp_path, monkeypatch):
    ws = _build_workspace(tmp_path)
    _setup_env(monkeypatch, ws)
    import importlib

    from lacuna.tools import recon_server
    importlib.reload(recon_server)
    out = _read_json(recon_server._tool_data_sinks({"repo": "tiny"}))
    facets = out.get("facets", {})
    handles = out.get("handles") or []
    has_sink_category = (
        any(str(k).startswith("sink:") for k in facets.get("by_category", {}))
        or any(h.get("category", "").startswith("sink:") for h in handles)
    )
    assert has_sink_category, (
        f"data_sinks must use 'sink:*' category labels; "
        f"facets={facets}, handles={handles}"
    )


def test_custom_semgrep_scan_returns_facets(tmp_path, monkeypatch):
    """custom_semgrep_scan must read its language stats from
    ``files_by_lang`` (the actual facet) and surface a facets dict in
    its result."""
    ws = _build_workspace(tmp_path)
    _setup_env(monkeypatch, ws)
    import importlib

    from lacuna.tools import recon_server
    importlib.reload(recon_server)
    out = _read_json(
        recon_server._tool_custom_semgrep_scan({"repo": "tiny"})
    )
    assert "facets" in out, f"missing facets in result: {out}"
