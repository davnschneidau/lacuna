"""Tests for the lacuna-kg MCP server tool surface."""
from __future__ import annotations

import asyncio
import json

import pytest

# The MCP package only ships inside the Lacuna Docker image. Local test
# runs against a clean venv shouldn't fail loudly here — skip cleanly.
pytest.importorskip("mcp")


def _run(coro):
    """Helper: run an async coro in a new event loop.

    We don't pull in pytest-asyncio just for these schema/wiring tests;
    each test is self-contained and the synchronous wrapper keeps them
    portable across CI environments that may not have the plugin
    installed.
    """
    return asyncio.run(coro)


def test_every_tool_definition_has_required_field():
    """Strict MCP clients refuse to call a tool whose schema omits
    ``required``. Make sure every tool we expose has the field, even when
    it's an empty list."""
    from lacuna.tools.kg_server import list_tools
    tools = _run(list_tools())
    assert tools, "kg server must expose at least one tool"
    missing = [t.name for t in tools if "required" not in (t.inputSchema or {})]
    assert not missing, (
        f"every tool's inputSchema must declare `required`; missing: {missing}"
    )


def test_tool_names_are_snake_case_not_dotted():
    """MCP tool names must match ``[a-zA-Z0-9_-]+`` — dots are rejected by
    most clients. Verify the rename from ``kg.read.xyz`` -> ``kg_read_xyz``."""
    from lacuna.tools.kg_server import list_tools
    tools = _run(list_tools())
    bad = [t.name for t in tools if "." in t.name]
    assert not bad, f"dotted tool names break MCP validation: {bad}"


def test_legacy_dotted_tool_name_translates(monkeypatch, tmp_path):
    """Backward compatibility: agents that still send the dotted form
    should be transparently routed to the snake_case handler."""
    monkeypatch.setenv("LACUNA_KG_PATH", str(tmp_path / "kg.db"))
    from lacuna.kg import open_kg
    kg = open_kg()
    kg.initialize()
    kg.close()

    from lacuna.tools.kg_server import call_tool
    res_dotted = _run(call_tool("kg.read.application_model", {}))
    res_snake = _run(call_tool("kg_read_application_model", {}))
    assert res_dotted and res_snake, "both forms must produce output"
    assert res_dotted[0].text == res_snake[0].text, (
        "dotted name must route to the same handler as snake_case"
    )


def test_capability_graph_supports_pagination():
    """The ``kg_read_capability_graph`` tool must declare ``page`` and
    ``page_size`` properties on its inputSchema."""
    from lacuna.tools.kg_server import list_tools
    tools = _run(list_tools())
    cg = next((t for t in tools if t.name == "kg_read_capability_graph"), None)
    assert cg is not None, "kg_read_capability_graph tool missing"
    props = cg.inputSchema.get("properties", {})
    assert "page" in props
    assert "page_size" in props


def test_write_finding_handles_cwes_list(monkeypatch, tmp_path):
    """``kg_write_finding`` must accept ``cwes`` as a JSON array, not just
    a comma string."""
    monkeypatch.setenv("LACUNA_KG_PATH", str(tmp_path / "kg.db"))
    from lacuna.kg import open_kg
    kg = open_kg()
    kg.initialize()

    from lacuna.kg.client import Hypothesis
    hyp = Hypothesis(
        hunter="hunter-injection", shape="sqli",
        repo="api", file="db.py", line=1,
        description="x", confidence=0.6,
    )
    kg.add_hypothesis(hyp)
    kg.close()

    from lacuna.tools.kg_server import call_tool
    out = _run(call_tool("kg_write_finding", {
        "hypothesis_id": hyp.id,
        "title": "SQLi in /search",
        "severity": "high",
        "cwes": ["CWE-89", "CWE-20"],
        "repos_involved": ["api"],
        "validator_summary": "confirmed",
    }))
    payload = json.loads(out[0].text)
    assert "error" not in payload, payload
    assert "finding_id" in payload

    kg = open_kg()
    f = kg.get_finding(payload["finding_id"])
    kg.close()
    assert isinstance(f["cwes"], list)
    assert "CWE-89" in f["cwes"]
