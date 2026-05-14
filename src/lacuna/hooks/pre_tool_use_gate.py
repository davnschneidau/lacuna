#!/usr/bin/env python3
"""
PreToolUse hook — gates destructive tools.

Responsibilities:
1. In SAST-only mode: block all lacuna-dast.* tool calls.
2. In SAST+DAST mode: enforce destructive-verb policy from the manifest.
3. Log every tool call for audit.
4. Apply per-target rate limits.

The hook is invoked by Claude Code before any tool call. It receives the
tool name and arguments via stdin and returns allow/deny via stdout.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg  # noqa: E402

# Destructive HTTP verbs that require explicit allow-listing
DESTRUCTIVE_HTTP_VERBS = {"PUT", "PATCH", "DELETE"}

# In-memory rate limiter (process-local; one PreToolUse process invocation
# per tool call so this only catches bursts within a single hook invocation)
_LAST_REQUEST_TS: dict[str, float] = {}


def _parse_manifest_dast_safety() -> dict:
    """Read DAST safety settings from the manifest if present."""
    manifest_path = os.environ.get("LACUNA_MANIFEST_RESOLVED", "")
    if not manifest_path or not Path(manifest_path).exists():
        return {}
    try:
        import yaml  # type: ignore
        with open(manifest_path) as f:
            doc = yaml.safe_load(f) or {}
        return (doc.get("scan", {}) or {}).get("dast", {}).get("safety", {}) or {}
    except Exception:
        return {}


def _block(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _allow() -> dict:
    return {"decision": "allow"}


def main() -> int:
    raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}
    tool_name = hook_input.get("tool_name", "")
    tool_args = hook_input.get("tool_input", {}) or {}
    agent = hook_input.get("agent", "unknown")
    mode = os.environ.get("LACUNA_MODE", "sast")

    kg = open_kg()
    decision: dict

    try:
        # ── 1. SAST-only mode: deny DAST tools ──────────────────────────────
        if mode == "sast" and tool_name.startswith("lacuna-dast"):
            decision = _block(
                f"DAST tool '{tool_name}' is unavailable in SAST-only mode. "
                f"Use lacuna-recon tools for static analysis."
            )

        # ── 2. SAST+DAST mode: enforce safety contract ──────────────────────
        elif tool_name.startswith("lacuna-dast"):
            safety = _parse_manifest_dast_safety()
            destructive_policy = safety.get("destructive_methods", "deny")
            allowed_destructive = set(
                m.upper() for m in safety.get("allowed_destructive_methods", [])
            )
            rate_limit_rps = float(safety.get("rate_limit_rps", 10))

            method = (tool_args.get("method") or "").upper()
            if method in DESTRUCTIVE_HTTP_VERBS:
                if destructive_policy == "deny" and method not in allowed_destructive:
                    decision = _block(
                        f"Destructive method {method} blocked by safety policy. "
                        f"Add to manifest scan.dast.safety.allowed_destructive_methods "
                        f"to permit."
                    )
                else:
                    decision = _allow()
            else:
                decision = _allow()

            # Rate limit per target (only if allowed so far)
            if decision["decision"] == "allow":
                target = tool_args.get("url", "global")
                last = _LAST_REQUEST_TS.get(target, 0)
                min_interval = 1.0 / max(rate_limit_rps, 0.1)
                if time.time() - last < min_interval:
                    time.sleep(min_interval - (time.time() - last))
                _LAST_REQUEST_TS[target] = time.time()

        # ── 3. Recon and KG tools: always allowed ───────────────────────────
        else:
            decision = _allow()

        # ── 4. Audit log every tool call regardless of decision ─────────────
        kg.append_event(agent, "tool_call_decision", {
            "tool": tool_name,
            "args_keys": list(tool_args.keys()) if isinstance(tool_args, dict) else [],
            "decision": decision["decision"],
            "reason": decision.get("reason"),
        })
    finally:
        kg.close()

    print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    sys.exit(main())
