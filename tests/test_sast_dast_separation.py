"""End-to-end SAST/DAST separation tests.

These tests pin the architectural invariant that a SAST-only scan
never sees the DAST MCP server in any of three places:

1. The ``.mcp.json`` that the harness writes (``_write_mcp_config``).
2. The PreSessionValidate hook (rejects the start).
3. The DAST server itself (refuses every tool call when the scan
   kind disagrees).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lacuna.harness.workspace import _write_mcp_config
from lacuna.kind import ScanKind, ScanKindSpec, ScanScope

SRC = Path(__file__).parent.parent / "src"


# ─── 1. .mcp.json wiring ─────────────────────────────────────────────────────

def test_mcp_config_omits_dast_in_sast_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("LACUNA_SRC_ROOT", str(SRC))
    spec = ScanKindSpec(kind=ScanKind.SAST, scope=ScanScope.FULL)
    _write_mcp_config(tmp_path, spec=spec)
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    servers = mcp["mcpServers"]
    assert "lacuna-recon" in servers
    assert "lacuna-kg" in servers
    assert "lacuna-dast" not in servers, (
        "SAST-only scans MUST NOT register lacuna-dast."
    )


def test_mcp_config_includes_dast_in_sast_dast_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("LACUNA_SRC_ROOT", str(SRC))
    spec = ScanKindSpec(kind=ScanKind.SAST_DAST, scope=ScanScope.FULL)
    _write_mcp_config(tmp_path, spec=spec)
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    servers = mcp["mcpServers"]
    assert {"lacuna-recon", "lacuna-kg", "lacuna-dast"} <= set(servers)
    dast_env = servers["lacuna-dast"]["env"]
    assert dast_env["LACUNA_SCAN_KIND"] == "sast_dast"


def test_mcp_config_in_diff_scope_still_omits_dast_when_kind_is_sast(
    tmp_path, monkeypatch,
):
    """Diff scope is SAST-shaped; it must not flip on DAST."""
    monkeypatch.setenv("LACUNA_SRC_ROOT", str(SRC))
    spec = ScanKindSpec(kind=ScanKind.SAST, scope=ScanScope.DIFF)
    _write_mcp_config(tmp_path, spec=spec)
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert "lacuna-dast" not in mcp["mcpServers"]


# ─── 2. PreSessionValidate hook ──────────────────────────────────────────────

def _run_hook(module: str, stdin_obj: dict, env: dict) -> dict:
    base_env = {"PATH": os.environ.get("PATH", os.defpath)}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP",
                "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
                "LANG", "LC_ALL", "LC_CTYPE"):
        v = os.environ.get(key)
        if v is not None:
            base_env[key] = v
    child_env = {**base_env, **env, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", module],
        input=json.dumps(stdin_obj),
        capture_output=True, text=True, env=child_env,
    )
    return json.loads(proc.stdout.strip())


def test_presession_validate_rejects_sast_with_dast_in_mcp(tmp_path):
    """If the harness misconfigures .mcp.json, fail fast."""
    # Hand-craft a broken .mcp.json that registers DAST in SAST mode.
    mcp = {
        "mcpServers": {
            "lacuna-recon": {"command": "python3", "args": [], "env": {}},
            "lacuna-kg": {"command": "python3", "args": [], "env": {}},
            "lacuna-dast": {"command": "python3", "args": [], "env": {}},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp))

    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
        "LACUNA_WORKSPACE": str(tmp_path),
        "LACUNA_MODE": "sast",
    }
    result = _run_hook("lacuna.hooks.pre_session_validate", {}, env)
    assert result["decision"] == "deny"
    assert "SAST-only" in result["reason"]


def test_presession_validate_rejects_dast_without_allowed_hosts(tmp_path):
    """A DAST scan with no allowed_hosts is a wasted scan — refuse it."""
    mcp = {
        "mcpServers": {
            "lacuna-recon": {"command": "python3", "args": [], "env": {}},
            "lacuna-kg": {"command": "python3", "args": [], "env": {}},
            "lacuna-dast": {"command": "python3", "args": [], "env": {}},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp))
    manifest = tmp_path / "app.lacuna.yaml"
    manifest.write_text("application:\n  name: test\nscan:\n  dast: {}\n")

    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
        "LACUNA_WORKSPACE": str(tmp_path),
        "LACUNA_MODE": "sast+dast",
        "LACUNA_MANIFEST_RESOLVED": str(manifest),
    }
    result = _run_hook("lacuna.hooks.pre_session_validate", {}, env)
    assert result["decision"] == "deny"
    assert "allowed_hosts" in result["reason"]


def test_presession_validate_allows_correctly_configured_sast(tmp_path):
    mcp = {
        "mcpServers": {
            "lacuna-recon": {"command": "python3", "args": [], "env": {}},
            "lacuna-kg": {"command": "python3", "args": [], "env": {}},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp))
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
        "LACUNA_WORKSPACE": str(tmp_path),
        "LACUNA_MODE": "sast",
    }
    result = _run_hook("lacuna.hooks.pre_session_validate", {}, env)
    assert result["decision"] == "allow"
    assert result["scan_kind"] == "sast"


def test_presession_validate_allows_correctly_configured_sast_dast(tmp_path):
    mcp = {
        "mcpServers": {
            "lacuna-recon": {"command": "python3", "args": [], "env": {}},
            "lacuna-kg": {"command": "python3", "args": [], "env": {}},
            "lacuna-dast": {"command": "python3", "args": [], "env": {}},
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp))
    manifest = tmp_path / "app.lacuna.yaml"
    manifest.write_text(
        "application:\n  name: test\n"
        "scan:\n  dast:\n    target:\n      allowed_hosts: ['localhost']\n"
    )
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
        "LACUNA_WORKSPACE": str(tmp_path),
        "LACUNA_MODE": "sast+dast",
        "LACUNA_MANIFEST_RESOLVED": str(manifest),
    }
    result = _run_hook("lacuna.hooks.pre_session_validate", {}, env)
    assert result["decision"] == "allow"
    assert result["scan_kind"] == "sast_dast"


# ─── 3. DAST server kind-guard ──────────────────────────────────────────────

# These two tests need the ``mcp`` Python package because dast_server
# imports it at module load. We skip them locally when ``mcp`` isn't
# installed; the CI image always has it.
try:
    import mcp  # noqa: F401
    _HAVE_MCP = True
except ImportError:
    _HAVE_MCP = False

dast_runtime = pytest.mark.skipif(
    not _HAVE_MCP, reason="requires the mcp Python package",
)


def _run_async(coro):
    import asyncio
    return asyncio.run(coro)


@dast_runtime
def test_dast_server_refuses_every_tool_in_sast_kind(monkeypatch, tmp_path):
    """The DAST MCP server is the *last* line of defense for SAST/DAST separation."""
    monkeypatch.setenv("LACUNA_MODE", "sast")
    monkeypatch.setenv("LACUNA_DAST_KIND_GUARD", "1")

    from lacuna.tools.dast_server import call_tool

    result = _run_async(call_tool(
        "http_request",
        {"method": "GET", "url": "https://target.example"},
    ))
    text = result[0].text
    payload = json.loads(text)
    assert "error" in payload
    assert "not available in scan_kind=sast" in payload["error"]


@dast_runtime
def test_dast_server_kind_guard_can_be_disabled_in_unit_tests(
    monkeypatch, tmp_path,
):
    """Tests that exercise individual DAST tools may opt out."""
    monkeypatch.setenv("LACUNA_MODE", "sast")
    monkeypatch.setenv("LACUNA_DAST_KIND_GUARD", "0")
    monkeypatch.setenv(
        "LACUNA_MANIFEST_RESOLVED", str(tmp_path / "missing.yaml"),
    )

    from lacuna.tools.dast_server import call_tool

    result = _run_async(call_tool(
        "http_request",
        {"method": "GET", "url": "https://target.example"},
    ))
    text = result[0].text
    payload = json.loads(text)
    assert "not available in scan_kind" not in payload.get("error", "")


# ─── 4. KG kind columns ─────────────────────────────────────────────────────

def test_kg_initialize_adds_scan_kind_columns(tmp_kg):
    """Phase-1 additive migration: ``scan_kind`` lives on every core table."""
    conn = tmp_kg._conn  # noqa: SLF001
    for table in ("hypotheses", "findings", "primitives", "chains"):
        cols = [
            row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
        ]
        assert "scan_kind" in cols, f"{table} missing scan_kind column"
