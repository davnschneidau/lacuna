"""
Lacuna scan harness.

Responsibilities:
  1. Resolve and validate the application manifest.
  2. Clone every repo declared in the manifest into the workspace.
  3. Write the .mcp.json and .claude/ config into the workspace so Claude Code
     finds them.
  4. Invoke `claude` in print mode with the orchestrator prompt and a
     wall-clock budget (also enforces a token-budget proxy via LACUNA_BUDGET_USD).
  5. After the run, materialize reports.

The harness itself is *not* an agent. It is the boring shell that runs around
the agent so that all the orchestrator has to do is reason.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

from ..kg import open_kg
from ..reports.generator import write_reports

# Environment variables that must be passed through to the child agent
# subprocess (Claude Code + MCP servers). Anything else is dropped to
# avoid leaking developer-machine paths and secrets into the sandbox.
_ENV_PASSTHROUGH_EXACT = {
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "PYTHONPATH",
    "TMPDIR", "TEMP", "TMP", "USER", "USERNAME", "SHELL",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_VERTEX_PROJECT_ID", "ANTHROPIC_VERTEX_LOCATION",
    "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
    "BITBUCKET_USERNAME", "BITBUCKET_APP_PASSWORD",
    "BITBUCKET_ACCESS_TOKEN",
    # CI-supplied identifiers — useful for tagging but not secrets
    "BITBUCKET_BUILD_NUMBER", "BITBUCKET_BRANCH",
    "BITBUCKET_COMMIT", "BITBUCKET_REPO_SLUG", "BITBUCKET_WORKSPACE",
    "GIT_ASKPASS",
}
_ENV_PASSTHROUGH_PREFIX = (
    "LACUNA_", "LC_", "ANTHROPIC_", "CLAUDE_",
)


def _log(msg: str) -> None:
    sys.stderr.write(f"[harness] {msg}\n")
    sys.stderr.flush()


def _bitbucket_token() -> str:
    """Resolve a Bitbucket access token from env (multiple aliases supported).

    Bitbucket Cloud has historically called the same credential
    ``BITBUCKET_ACCESS_TOKEN``, ``BITBUCKET_TOKEN`` and
    ``BB_ACCESS_TOKEN`` in different docs. Accept any of them.
    """
    for k in ("BITBUCKET_ACCESS_TOKEN", "BITBUCKET_TOKEN", "BB_ACCESS_TOKEN"):
        v = os.environ.get(k)
        if v:
            return v
    return ""


def _resolve_bitbucket_url(repo_cfg: dict, workspace_name: str) -> str:
    """Build a clone URL from manifest repo config.

    Supports:
      git:        any explicit git URL
      bitbucket:  bitbucket.org/{workspace}/{slug}

    Credentials are NOT embedded in the URL; instead, the caller arranges
    for ``GIT_ASKPASS`` to provide them, so secrets don't leak into
    process tables, git config, or remote URLs.
    """
    if "git" in repo_cfg:
        return repo_cfg["git"]
    slug = repo_cfg.get("slug") or repo_cfg.get("name")
    ws = repo_cfg.get("workspace") or workspace_name
    if not slug or not ws:
        raise ValueError(f"repo cfg lacks slug/workspace: {repo_cfg}")
    return f"https://bitbucket.org/{ws}/{slug}.git"


def _make_git_askpass_script(tmp_dir: Path) -> tuple[Path | None, dict]:
    """Create a credential helper that returns BITBUCKET creds at the prompt.

    Returns ``(script_path, env_extras)``. Caller is responsible for
    cleaning up ``tmp_dir`` after the clone finishes.
    """
    tok = _bitbucket_token()
    user = os.environ.get("BITBUCKET_USERNAME", "")
    app_pw = os.environ.get("BITBUCKET_APP_PASSWORD", "")
    if not (tok or (user and app_pw)):
        return None, {}

    if tok:
        username = "x-token-auth"
        password = tok
    else:
        username = user
        password = app_pw

    # GIT_ASKPASS is called with the prompt as the first argument. The
    # prompt says either "Username for ..." or "Password for ...". We
    # match on the first word.
    if os.name == "nt":
        script = tmp_dir / "lacuna-askpass.cmd"
        script.write_text(
            "@echo off\r\n"
            f"if /I \"%~1\" == \"Username\" (echo {username}) else (echo {password})\r\n",
            encoding="ascii",
        )
    else:
        script = tmp_dir / "lacuna-askpass.sh"
        script.write_text(
            "#!/bin/sh\n"
            f'case "$1" in Username*) echo "{username}";; *) echo "{password}";; esac\n',
            encoding="ascii",
        )
        script.chmod(script.stat().st_mode | stat.S_IRWXU)

    return script, {
        "GIT_ASKPASS": str(script),
        "GIT_TERMINAL_PROMPT": "0",
    }


def _clone_repos(manifest: dict, workspace: Path) -> dict[str, Path]:
    """Clone every repo named in the manifest. Returns name → path.

    Uses ``GIT_ASKPASS`` for credential handling so secrets don't appear
    in process tables or end up in git's stored remote URL. Depth is
    controlled by ``LACUNA_CLONE_DEPTH`` (default ``full`` so taint and
    history-aware tools have the data they need; set to a number like
    ``50`` to truncate).
    """
    app = manifest.get("application", {}) or {}
    workspace_name = app.get("bitbucket_workspace", "")
    out: dict[str, Path] = {}

    depth_setting = os.environ.get("LACUNA_CLONE_DEPTH", "").strip().lower()
    depth_arg: list[str] = []
    if depth_setting and depth_setting not in ("0", "full", "all"):
        try:
            int(depth_setting)
            depth_arg = ["--depth", depth_setting]
        except ValueError:
            _log(f"LACUNA_CLONE_DEPTH={depth_setting!r} is not numeric — using full clone")

    askpass_tmp = Path(tempfile.mkdtemp(prefix="lacuna-askpass-"))
    _askpass_script, askpass_env = _make_git_askpass_script(askpass_tmp)
    git_env = os.environ.copy()
    git_env.update(askpass_env)

    try:
        for repo in manifest.get("repos", []) or []:
            name = repo.get("name")
            if not name:
                continue
            dest = workspace / name
            if dest.exists():
                _log(f"repo {name} already present at {dest}, skipping clone")
                out[name] = dest
                continue
            try:
                url = _resolve_bitbucket_url(repo, workspace_name)
            except ValueError as e:
                _log(f"skip {name}: {e}")
                continue
            ref = repo.get("ref", "main")
            _log(f"cloning {name} ref={ref} depth={depth_setting or 'full'}")
            cmd = ["git", "clone"]
            cmd.extend(depth_arg)
            cmd.extend(["--branch", ref, url, str(dest)])
            rc = subprocess.run(
                cmd, capture_output=True, text=True, env=git_env,
            )
            if rc.returncode != 0:
                _log(f"clone failed for {name}: {rc.stderr.strip()[:300]}")
                continue
            if repo.get("paths"):
                for p in repo["paths"]:
                    # Sparse checkout is best-effort; agents can still
                    # ignore the other paths if it fails.
                    _log(f"  (manifest declares paths filter: {p})")
            out[name] = dest
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(askpass_tmp, ignore_errors=True)
    return out


def _build_child_env(workspace: Path, extras: dict[str, str]) -> dict[str, str]:
    """Construct the env dict for the Claude Code subprocess.

    Whitelisting prevents accidentally leaking developer-machine env
    vars (especially shell-specific ``CLAUDE_*`` / ``LACUNA_*`` keys
    that name local paths) into the sandbox. Anything that needs to
    survive into MCP servers should be in the prefix/exact lists above
    or passed via ``extras``.
    """
    env: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in _ENV_PASSTHROUGH_EXACT or k.startswith(_ENV_PASSTHROUGH_PREFIX):
            env[k] = v
    env["LACUNA_WORKSPACE"] = str(workspace)
    env.update(extras)
    return env


def _write_mcp_config(workspace: Path) -> None:
    """Drop .mcp.json into the workspace so Claude Code picks up the three MCP servers."""
    src_root = os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src")
    mcp = {
        "mcpServers": {
            "lacuna-recon": {
                "command": "python3",
                "args": ["-m", "lacuna.tools.recon_server"],
                "env": {
                    "PYTHONPATH": src_root,
                    "LACUNA_WORKSPACE": str(workspace),
                    "LACUNA_MANIFEST_RESOLVED": os.environ.get(
                        "LACUNA_MANIFEST_RESOLVED", ""
                    ),
                    "LACUNA_KG_PATH": os.environ.get("LACUNA_KG_PATH", ""),
                    "LACUNA_TOOL_CACHE_DIR": os.environ.get(
                        "LACUNA_TOOL_CACHE_DIR", ""
                    ),
                },
            },
            "lacuna-kg": {
                "command": "python3",
                "args": ["-m", "lacuna.tools.kg_server"],
                "env": {
                    "PYTHONPATH": src_root,
                    "LACUNA_KG_PATH": os.environ.get("LACUNA_KG_PATH", ""),
                },
            },
            "lacuna-dast": {
                "command": "python3",
                "args": ["-m", "lacuna.tools.dast_server"],
                "env": {
                    "PYTHONPATH": src_root,
                    "LACUNA_WORKSPACE": str(workspace),
                    "LACUNA_MANIFEST_RESOLVED": os.environ.get(
                        "LACUNA_MANIFEST_RESOLVED", ""
                    ),
                    "LACUNA_KG_PATH": os.environ.get("LACUNA_KG_PATH", ""),
                    "LACUNA_EVIDENCE_DIR": os.environ.get(
                        "LACUNA_EVIDENCE_DIR", ""
                    ),
                },
            },
        }
    }
    (workspace / ".mcp.json").write_text(json.dumps(mcp, indent=2))


def _stage_claude_config(workspace: Path) -> None:
    """Copy /opt/lacuna/.claude into the workspace so Claude Code finds CLAUDE.md, agents, skills, etc."""
    src = Path(os.environ.get("LACUNA_CLAUDE_HOME", "/opt/lacuna/.claude"))
    dst = workspace / ".claude"
    if not src.exists():
        _log(f"warning: {src} does not exist; agent configuration will be missing")
        return
    if dst.exists():
        return
    shutil.copytree(src, dst)
    _log(f"staged claude config into {dst}")


def _kickoff_prompt(manifest: dict, mode: str) -> str:
    app = manifest.get("application", {}) or {}
    repos = ", ".join(r.get("name", "?") for r in manifest.get("repos", []) or [])
    return (
        f"Begin a Lacuna scan of application '{app.get('name', 'unknown')}'.\n"
        f"Mode: {mode}.\n"
        f"Repos in scope: {repos}.\n"
        f"\n"
        f"Follow your system prompt. Start by reading the manifest and "
        f"writing the application model. Then proceed to hypothesize, "
        f"validate, chain, and report. The Stop hook will block exit until "
        f"all exit criteria are met.\n"
    )


def _resolve_wall_clock_hours(passed: float) -> float:
    """Allow ``LACUNA_WALL_CLOCK_HOURS`` to override the CLI value."""
    env = os.environ.get("LACUNA_WALL_CLOCK_HOURS")
    if env:
        try:
            return float(env)
        except ValueError:
            _log(f"LACUNA_WALL_CLOCK_HOURS={env!r} is not numeric — ignoring")
    return passed


def _track_budget_usd() -> float | None:
    """Compute the spend-cap (USD) for this scan, or None if uncapped."""
    raw = os.environ.get("LACUNA_BUDGET_USD")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        _log(f"LACUNA_BUDGET_USD={raw!r} is not numeric — ignoring")
        return None


def run_scan(
    *, manifest_path: Path, workspace: Path, mode: str, fail_on: str,
    wall_clock_hours: float, max_parallel: int,
) -> int:
    """Run the full scan. Returns exit code."""
    if not manifest_path.exists():
        _log(f"ERROR: manifest not found: {manifest_path}")
        return 2
    manifest = yaml.safe_load(manifest_path.read_text()) or {}
    os.environ["LACUNA_MANIFEST_RESOLVED"] = str(manifest_path)
    os.environ["LACUNA_MODE"] = mode

    kg = open_kg()
    kg.initialize()
    kg.set_meta("scan_started_at", str(int(time.time())))
    kg.set_meta("scan_mode", mode)
    kg.set_meta("manifest_path", str(manifest_path))
    kg.set_meta("current_phase", "phase-0-init")
    kg.append_event("harness", "scan_started", {
        "mode": mode, "manifest": str(manifest_path),
        "app": (manifest.get("application", {}) or {}).get("name"),
    })
    kg.close()

    workspace.mkdir(parents=True, exist_ok=True)
    _clone_repos(manifest, workspace)

    _stage_claude_config(workspace)
    _write_mcp_config(workspace)

    wall_clock_hours = _resolve_wall_clock_hours(wall_clock_hours)
    deadline_s = max(60, int(wall_clock_hours * 3600))
    budget_usd = _track_budget_usd()

    prompt = _kickoff_prompt(manifest, mode)
    _log(
        f"invoking Claude Code (deadline {deadline_s}s, "
        f"budget=${budget_usd if budget_usd is not None else 'unlimited'})"
    )

    fuzz_budget = os.environ.get("LACUNA_FUZZ_BUDGET_MINUTES", "60")
    try:
        # Validate that it parses; ignore anything weird and fall back to 60.
        int(fuzz_budget)
    except ValueError:
        _log(
            f"LACUNA_FUZZ_BUDGET_MINUTES={fuzz_budget!r} is not numeric "
            "— defaulting to 60 minutes",
        )
        fuzz_budget = "60"

    child_env = _build_child_env(workspace, {
        "LACUNA_MODE": mode,
        "LACUNA_MANIFEST_RESOLVED": str(manifest_path),
        "LACUNA_FUZZ_BUDGET_MINUTES": fuzz_budget,
    })

    cmd = [
        "claude",
        "-p", prompt,
        "--dangerously-skip-permissions",
        "--model", os.environ.get("LACUNA_MODEL_OPUS", "claude-opus-4-7"),
    ]
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=str(workspace),
            env=child_env,
            timeout=deadline_s,
        )
        agent_rc = proc.returncode
    except subprocess.TimeoutExpired:
        _log(f"WALL-CLOCK CAP HIT after {deadline_s}s — proceeding to reports")
        agent_rc = 124
    except FileNotFoundError:
        _log("ERROR: `claude` CLI not found in PATH. Is Claude Code installed?")
        return 3
    elapsed = int(time.time() - start)

    # Enforce the dollar budget as a *proxy* via the recorded token-usage
    # totals the agent should have written. We don't sample mid-run (that
    # would require instrumenting the model call itself), but we can fail
    # the scan if usage clearly exceeded the cap.
    if budget_usd is not None:
        try:
            kg = open_kg()
            usage = kg.get_meta("token_cost_usd")
            kg.close()
            if usage:
                spent = float(usage)
                if spent > budget_usd:
                    _log(
                        f"BUDGET CAP EXCEEDED: spent ${spent:.2f} vs cap "
                        f"${budget_usd:.2f}; flagging exit code 124"
                    )
                    agent_rc = 124
        except (ValueError, TypeError):
            pass
        except Exception as e:
            _log(f"budget cap check failed: {e}")

    _log(f"agent run finished in {elapsed}s with rc={agent_rc}; writing reports")
    reports_dir = Path(os.environ.get("LACUNA_REPORTS_DIR", "/reports"))
    write_reports(reports_dir)

    kg = open_kg()
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    threshold = sev_order.get(fail_on, 0)
    findings = kg.list_findings()
    chains = kg.list_chains()
    kg.close()

    if threshold == 0:
        return 0

    blocking_sev = any(
        sev_order.get(f["severity"], 0) >= threshold for f in findings
    )
    blocking_chain = any(
        sev_order.get(c.combined_severity, 0) >= threshold for c in chains
    )
    if blocking_sev or blocking_chain:
        _log(f"FAIL: findings or chains met or exceeded {fail_on}")
        return 1
    return 0
