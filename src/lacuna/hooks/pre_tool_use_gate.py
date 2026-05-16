#!/usr/bin/env python3
"""
PreToolUse hook -- gates destructive tools.

Responsibilities:
1. In SAST-only mode (``LACUNA_MODE`` in {``"sast"``, ``"diff"``}):
   block all ``lacuna-dast.*`` tool calls. Diff mode is a SAST-shaped
   workflow scoped to the diff; it has no business making HTTP
   requests against a live target.
2. In SAST+DAST mode: enforce destructive-verb policy from the manifest.
3. Log every tool call for audit.
4. Apply per-target rate limits -- **deny then retry-after**, not
   "allow then sleep". Sleeping inside a hook lets the underlying tool
   call land before the bucket has refilled (because the rate-limit
   decision is made on the *previous* call, not this one). The fix is
   to refuse the over-budget call and tell the agent when to retry; the
   agent then waits in its own retry loop.

The hook is invoked by Claude Code before any tool call. It receives the
tool name and arguments via stdin and returns allow/deny via stdout.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg
from lacuna.kind import is_sast_only_mode, parse_legacy_mode

DESTRUCTIVE_HTTP_VERBS = {"PUT", "PATCH", "DELETE"}


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


def _block(reason: str, **extra) -> dict:
    out = {"decision": "deny", "reason": reason}
    out.update(extra)
    return out


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
        # ── 1. SAST-only modes: deny DAST tools ─────────────────────────────
        # The kind taxonomy in ``lacuna.kind`` is the source of truth.
        # Diff mode is SAST-shaped scope, never DAST.
        spec = parse_legacy_mode(mode)
        if is_sast_only_mode(mode) and tool_name.startswith("lacuna-dast"):
            decision = _block(
                f"DAST tool '{tool_name}' is unavailable in SAST-only mode "
                f"(LACUNA_MODE='{mode}', scan_kind={spec.kind.value}). "
                f"Use lacuna-recon tools for static analysis. "
                f"To run DAST, re-launch with LACUNA_MODE=sast+dast."
            )

        # ── 2. SAST+DAST mode: enforce safety contract ──────────────────────
        elif tool_name.startswith("lacuna-dast"):
            safety = _parse_manifest_dast_safety()
            destructive_policy = safety.get("destructive_methods", "deny")
            allowed_destructive = {
                m.upper() for m in safety.get("allowed_destructive_methods", [])
            }
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

            # ── Rate limit per agent — deny-then-retry, not allow-then-sleep
            #
            # The hook runs *before* the tool call lands. The previous
            # implementation sampled the bucket, then ``time.sleep``-ed,
            # then returned ``allow`` — so the over-budget call was always
            # allowed to land on the target, just delayed. From the
            # target's perspective the rate limit was still violated.
            #
            # The corrected policy is: if the bucket is empty, return
            # ``deny`` with a ``retry_after_s`` field. The hook does NOT
            # record this attempt against the bucket (so the agent can
            # actually retry). Genuine over-budget calls are refused, and
            # the bucket only counts allowed calls.
            if decision["decision"] == "allow":
                target = tool_args.get("url", "global")
                rate_limit_rps = max(rate_limit_rps, 0.1)
                window_s = 1.0
                recent_before = kg.count_hook_tool_calls(
                    agent, window_seconds=int(window_s),
                )
                if recent_before >= rate_limit_rps:
                    decision = _block(
                        f"Rate limit {rate_limit_rps:.2f} rps exceeded for "
                        f"agent '{agent}' (window={window_s:.1f}s, "
                        f"recent={recent_before}). Retry after the window "
                        f"resets.",
                        retry_after_s=window_s,
                        rate_limit_rps=rate_limit_rps,
                        window_seconds=window_s,
                        recent_in_window=recent_before,
                    )
                else:
                    kg.record_hook_tool_call(agent, f"dast:{target}")

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
