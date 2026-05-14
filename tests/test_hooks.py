"""Tests for the lifecycle hooks. Hooks are stdin/stdout subprocesses; we test the JSON contract."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).parent.parent / "src"


def _base_env() -> dict[str, str]:
    """Build a minimal child-process env that works on both POSIX and Windows.

    On Windows, ``python`` won't even start without ``SYSTEMROOT`` and the
    interpreter looks at ``PATHEXT`` to resolve executable suffixes. On
    POSIX we still want a sensible ``PATH``. Rather than hard-coding
    ``/usr/bin:/bin`` we inherit the relevant subset from the parent
    process.
    """
    env: dict[str, str] = {"PATH": os.environ.get("PATH", os.defpath)}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP",
                "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
                "LANG", "LC_ALL", "LC_CTYPE"):
        val = os.environ.get(key)
        if val is not None:
            env[key] = val
    return env


def _run_hook(module: str, stdin_obj: dict, env: dict) -> dict:
    """Invoke a hook module via `python -m`, feed stdin, parse stdout JSON."""
    child_env = {**_base_env(), **env, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", module],
        input=json.dumps(stdin_obj),
        capture_output=True, text=True,
        env=child_env,
    )
    out = proc.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise AssertionError(
            f"hook stdout was not valid JSON.\nstdout={out}\nstderr={proc.stderr}"
        ) from e


def test_session_start_initializes_kg(tmp_path, monkeypatch):
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_MODE": "sast",
        "LACUNA_MANIFEST": "app.lacuna.yaml",
        "LACUNA_SRC_ROOT": str(SRC),
    }
    result = _run_hook("lacuna.hooks.session_start", {}, env)
    assert result["decision"] == "allow"
    assert "additional_context" in result
    assert (tmp_path / "kg.db").exists()


def test_stop_hook_blocks_when_criteria_unmet(tmp_path, monkeypatch):
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
    }
    _run_hook("lacuna.hooks.session_start", {}, env)
    result = _run_hook(
        "lacuna.hooks.stop_continuation",
        {"agent": "orchestrator"}, env,
    )
    assert result["decision"] == "block"
    assert "reason" in result
    assert "Continue." in result["reason"]


def test_stop_hook_allows_subagents_freely(tmp_path):
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
    }
    _run_hook("lacuna.hooks.session_start", {}, env)
    result = _run_hook(
        "lacuna.hooks.stop_continuation",
        {"agent": "recon"}, env,
    )
    assert result["decision"] == "allow"


def test_precompact_flush_persists_hypothesis_draft(tmp_path):
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
    }
    _run_hook("lacuna.hooks.session_start", {}, env)
    transcript = """
some chatter
<hypothesis-draft>
{"hunter":"hunter-injection","shape":"sqli","repo":"api","file":"db.py","line":42,
 "description":"raw query","confidence":0.6}
</hypothesis-draft>
<next-actions>
Spawn validator on hyp-abc next.
</next-actions>
more chatter
"""
    result = _run_hook(
        "lacuna.hooks.pre_compact_flush",
        {"agent": "orchestrator", "transcript": transcript}, env,
    )
    assert result["decision"] == "allow"
    assert result["flushed"]["hypotheses"] == 1
    assert result["flushed"]["actions"] == 1


def test_pretooluse_denies_dast_in_sast_mode(tmp_path):
    env = {
        "LACUNA_KG_PATH": str(tmp_path / "kg.db"),
        "LACUNA_SRC_ROOT": str(SRC),
        "LACUNA_MODE": "sast",
    }
    _run_hook("lacuna.hooks.session_start", {}, env)
    result = _run_hook(
        "lacuna.hooks.pre_tool_use_gate",
        {
            "tool_name": "lacuna-dast.http_request",
            "tool_input": {"method": "GET", "url": "https://x"},
            "agent": "validator",
        }, env,
    )
    assert result["decision"] == "deny"
    assert "SAST-only mode" in result.get("reason", "")
