"""Tests for the harness env whitelist and credential plumbing."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest


def test_child_env_whitelist_drops_aws_creds(monkeypatch, tmp_path):
    """``_build_child_env`` is the seam where leaked env vars become a
    problem. AWS credentials living in the developer's shell must never
    survive into the Claude Code subprocess."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "very-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_leak")
    monkeypatch.setenv("LACUNA_MODE", "sast")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))

    from lacuna.harness.workspace import _build_child_env
    env = _build_child_env(tmp_path, {})

    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env.get("LACUNA_MODE") == "sast"
    assert env.get("LACUNA_WORKSPACE") == str(tmp_path)


def test_child_env_whitelist_keeps_anthropic_and_lacuna(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
    monkeypatch.setenv("CLAUDE_CODE_BIN", "/usr/local/bin/claude")
    monkeypatch.setenv("LACUNA_FUZZ_BUDGET_MINUTES", "30")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))

    from lacuna.harness.workspace import _build_child_env
    env = _build_child_env(tmp_path, {})
    assert env["ANTHROPIC_AUTH_TOKEN"] == "tok"
    assert env["CLAUDE_CODE_BIN"] == "/usr/local/bin/claude"
    assert env["LACUNA_FUZZ_BUDGET_MINUTES"] == "30"


def test_make_git_askpass_script_writes_executable(monkeypatch, tmp_path):
    """When credentials are configured, a per-scan askpass helper is
    produced. The script must exist on disk and the env entries the
    harness adds must include ``GIT_ASKPASS`` and disable terminal
    prompting (so a missing credential never hangs the scan)."""
    monkeypatch.setenv("BITBUCKET_USERNAME", "scanbot")
    monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "trout-feather-19")
    monkeypatch.delenv("BITBUCKET_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("BITBUCKET_TOKEN", raising=False)
    monkeypatch.delenv("BB_ACCESS_TOKEN", raising=False)

    from lacuna.harness.workspace import _make_git_askpass_script
    script, env = _make_git_askpass_script(tmp_path)
    assert script is not None
    assert script.exists(), f"askpass script should exist at {script}"
    assert env.get("GIT_ASKPASS") == str(script)
    assert env.get("GIT_TERMINAL_PROMPT") == "0"


def test_make_git_askpass_returns_none_when_no_creds(monkeypatch, tmp_path):
    """No credentials -> no askpass script -> caller leaves git alone."""
    for k in ("BITBUCKET_USERNAME", "BITBUCKET_APP_PASSWORD",
              "BITBUCKET_ACCESS_TOKEN", "BITBUCKET_TOKEN", "BB_ACCESS_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    from lacuna.harness.workspace import _make_git_askpass_script
    script, env = _make_git_askpass_script(tmp_path)
    assert script is None
    assert env == {}


def test_resolve_bitbucket_url_does_not_embed_credentials(monkeypatch):
    """The clone URL must NEVER contain user:pass — those go through
    GIT_ASKPASS. Embedding them in the URL puts them in process tables
    and git's stored remote."""
    monkeypatch.setenv("BITBUCKET_USERNAME", "scanbot")
    monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "secret")
    from lacuna.harness.workspace import _resolve_bitbucket_url
    url = _resolve_bitbucket_url(
        {"name": "lacuna", "workspace": "acme"},
        workspace_name="acme",
    )
    assert "@" not in url
    assert "scanbot" not in url
    assert "secret" not in url
    assert url == "https://bitbucket.org/acme/lacuna.git"


def test_wall_clock_timeout_kills_subprocess(tmp_path):
    """``subprocess.run(timeout=...)`` must actually fire on overruns.
    We don't run the full harness here — we just want a smoke check
    that the timeout machinery the harness relies on works on this
    platform.
    """
    sleeper = "import time; time.sleep(30)"
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(
            [sys.executable, "-c", sleeper], timeout=1,
        )
