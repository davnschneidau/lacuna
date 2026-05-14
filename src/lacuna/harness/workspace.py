"""
Lacuna scan harness.

Responsibilities:
  1. Resolve and validate the application manifest.
  2. Clone every repo declared in the manifest into the workspace.
  3. Write the .mcp.json and .claude/ config into the workspace so Claude Code
     finds them.
  4. Invoke `claude` in print mode with the orchestrator prompt and a wall-clock
     budget.
  5. After the run, materialize reports.

The harness itself is *not* an agent. It is the boring shell that runs around
the agent so that all the orchestrator has to do is reason.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from ..kg import open_kg
from ..reports.generator import write_reports


def _log(msg: str) -> None:
    sys.stderr.write(f"[harness] {msg}\n")
    sys.stderr.flush()


def _resolve_bitbucket_url(repo_cfg: dict, workspace_name: str) -> str:
    """Build a clone URL from manifest repo config.

    Supports:
      git:        any explicit git URL
      bitbucket:  bitbucket.org/{workspace}/{slug}
    """
    if "git" in repo_cfg:
        return repo_cfg["git"]
    slug = repo_cfg.get("slug") or repo_cfg.get("name")
    ws = repo_cfg.get("workspace") or workspace_name
    if not slug or not ws:
        raise ValueError(f"repo cfg lacks slug/workspace: {repo_cfg}")
    user = os.environ.get("BITBUCKET_USERNAME", "")
    app_pw = os.environ.get("BITBUCKET_APP_PASSWORD", "")
    tok = os.environ.get("BITBUCKET_ACCESS_TOKEN", "")
    if tok:
        return f"https://x-token-auth:{tok}@bitbucket.org/{ws}/{slug}.git"
    if user and app_pw:
        return f"https://{user}:{app_pw}@bitbucket.org/{ws}/{slug}.git"
    return f"https://bitbucket.org/{ws}/{slug}.git"


def _clone_repos(manifest: dict, workspace: Path) -> dict[str, Path]:
    """Clone every repo named in the manifest. Returns name → path."""
    app = manifest.get("application", {}) or {}
    workspace_name = app.get("bitbucket_workspace", "")
    out: dict[str, Path] = {}
    for repo in manifest.get("repos", []) or []:
        name = repo.get("name")
        if not name:
            continue
        dest = workspace / name
        if dest.exists():
            _log(f"repo {name} already present at {dest}, skipping clone")
            out[name] = dest
            continue
        url = _resolve_bitbucket_url(repo, workspace_name)
        ref = repo.get("ref", "main")
        _log(f"cloning {name} ref={ref}")
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            capture_output=True, text=True,
        )
        if rc.returncode != 0:
            _log(f"clone failed for {name}: {rc.stderr.strip()[:300]}")
            continue
        # If sparse-checkout requested
        if repo.get("paths"):
            for p in repo["paths"]:
                # Not actually sparse-checkout-ing here; agents can ignore
                # other paths. Real sparse impl would use git sparse-checkout.
                _log(f"  (manifest declares paths filter: {p})")
        out[name] = dest
    return out


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

    # Initialize KG
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

    # Clone repos
    workspace.mkdir(parents=True, exist_ok=True)
    _clone_repos(manifest, workspace)

    # Configure Claude Code
    _stage_claude_config(workspace)
    _write_mcp_config(workspace)

    # Build prompt + run Claude Code in non-interactive print mode
    prompt = _kickoff_prompt(manifest, mode)
    deadline_s = int(wall_clock_hours * 3600)
    _log(f"invoking Claude Code (deadline {deadline_s}s)")

    cmd = [
        "claude",
        "-p", prompt,
        "--dangerously-skip-permissions",
        "--model", os.environ.get("LACUNA_MODEL_OPUS", "claude-opus-4-7"),
    ]
    try:
        proc = subprocess.run(
            cmd, cwd=str(workspace),
            env=os.environ.copy(),
            timeout=deadline_s,
        )
        agent_rc = proc.returncode
    except subprocess.TimeoutExpired:
        _log(f"WALL-CLOCK CAP HIT after {deadline_s}s — proceeding to reports")
        agent_rc = 124
    except FileNotFoundError:
        _log("ERROR: `claude` CLI not found in PATH. Is Claude Code installed?")
        return 3

    # Always write reports, even if the agent timed out
    _log("writing reports")
    reports_dir = Path(os.environ.get("LACUNA_REPORTS_DIR", "/reports"))
    write_reports(reports_dir)

    # Decide exit code from fail_on
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
