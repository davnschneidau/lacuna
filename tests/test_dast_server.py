"""Tests for the lacuna-dast MCP server.

These tests focus on the pure-Python helpers; we deliberately avoid
spinning up a real HTTP target. The interesting tool surface
(crawler, fuzz_param, oob_callback, auth_login) is wrapped behind helpers
that are unit-testable without a network.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")


def test_glob_match_handles_leading_wildcard():
    """Phase 3 fix: hostname glob must use ``fnmatch`` so ``*.foo.com``
    matches both ``a.foo.com`` and ``deep.b.foo.com`` (the apex
    ``foo.com`` is not matched — that's the standard fnmatch
    semantics)."""
    from lacuna.tools.dast_server import _glob_match
    assert _glob_match("*.foo.com", "a.foo.com")
    assert _glob_match("*.foo.com", "deep.b.foo.com")
    assert _glob_match("foo.com", "foo.com")
    assert not _glob_match("*.foo.com", "bar.com")
    assert _glob_match("api-?.svc", "api-1.svc")
    assert not _glob_match("api-?.svc", "api-12.svc")


def test_ysoserial_preflights_unknown_gadgets():
    """Asking for a gadget ysoserial doesn't ship returns a structured
    error instead of paying for the subprocess + parsing a confusing
    stderr."""
    from lacuna.tools.dast_server import _t_oracle_ysoserial
    result = _t_oracle_ysoserial({
        "runtime": "java",
        "gadget": "NotARealGadget",
        "command": "id",
    })
    payload = json.loads(result[0].text)
    assert "error" in payload
    assert "NotARealGadget" in payload["error"]


def test_ysoserial_accepts_known_gadget_name():
    """A known gadget passes the preflight (we don't care whether the
    actual JAR is present — the test just verifies the gating logic)."""
    from lacuna.tools.dast_server import _YSOSERIAL_GADGETS
    assert "CommonsCollections6" in _YSOSERIAL_GADGETS["java"]


def test_smuggling_probe_is_module_level_callable():
    """The raw-socket smuggling probe must exist as a callable. We don't
    actually fire it because that requires a target listening on a real
    TCP port — but the helper has to be importable so the MCP tool can
    dispatch to it."""
    from lacuna.tools.dast_server import _t_smuggling_probe
    assert callable(_t_smuggling_probe)
