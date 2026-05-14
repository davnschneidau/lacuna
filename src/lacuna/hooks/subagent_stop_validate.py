#!/usr/bin/env python3
"""
SubagentStop hook — runs when a subagent decides it's done. Validates that
the subagent produced its expected output before allowing it to stop.

If a subagent stops prematurely (e.g. recon stopped without writing the
application model), this hook returns `block` to force continuation.

Each subagent has expected outputs declared in its contract:
    recon              → application_model_ready exit criterion
    hunter-*           → at least one hypothesis written, OR explicit
                         "no findings" event
    validator          → hypothesis status changed to confirmed|refuted|needs_human
    chain-builder      → at minimum, all primitives marked chain_explored
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg  # noqa: E402


def _check_recon(kg) -> str | None:
    if not kg.read_application_model():
        return (
            "Recon must write the application model to the KG before stopping. "
            "Call kg.write_application_model with a summary_md plus a facts dict "
            "containing service_map, cross_repo_calls, entrypoints, auth_surface, "
            "dependencies, secrets, iac_findings, hotspots, frameworks."
        )
    return None


def _check_hunter(kg, agent_name: str) -> str | None:
    # A hunter must have either produced hypotheses, or explicitly logged
    # "no findings" for the shapes it covers.
    hyps = [h for h in kg.list_hypotheses() if h["hunter"] == agent_name]
    no_findings_events = [
        e for e in kg.recent_events(n=200, event_type="hunter_no_findings")
        if e["agent"] == agent_name
    ]
    if not hyps and not no_findings_events:
        return (
            f"Hunter '{agent_name}' must either record at least one hypothesis "
            f"or log a 'hunter_no_findings' event explaining why no hypotheses "
            f"were produced before stopping."
        )
    return None


def _check_validator(kg, hyp_id: str | None) -> str | None:
    if not hyp_id:
        return None  # No specific hypothesis to validate
    hyps = [h for h in kg.list_hypotheses() if h["id"] == hyp_id]
    if not hyps:
        return None
    h = hyps[0]
    if h["status"] not in ("confirmed", "refuted", "needs_human"):
        return (
            f"Validator must update hypothesis {hyp_id} to confirmed, refuted, "
            f"or needs_human before stopping. Current status: {h['status']}."
        )
    # NEW in v2: If confirmed, require minimal_repro present.
    if h["status"] == "confirmed":
        # Look up the resulting finding(s)
        findings = [
            f for f in kg.list_findings()
            if f.get("hypothesis_id") == hyp_id
        ]
        for f in findings:
            r = kg.get_minimal_repro(f["id"])
            if r is None:
                return (
                    f"Validator confirmed hypothesis {hyp_id} (finding "
                    f"{f['id']}) but did NOT record a minimal_repro. "
                    f"Apply the `minimal-repro` skill and call "
                    f"kg.write.minimal_repro before stopping."
                )
    return None


def _check_skeptic(kg) -> str | None:
    # Skeptic must have reviewed every confirmed finding ≥ medium severity
    findings = [
        f for f in kg.list_findings()
        if f.get("severity") in ("critical", "high", "medium")
    ]
    if not findings:
        return None
    # We track skeptic reviews via events of type "skeptic_review"
    events = [
        e for e in kg.recent_events(n=2000, event_type="skeptic_review")
    ]
    reviewed_ids = {
        (e.get("payload") or {}).get("finding_id")
        for e in events
    }
    unreviewed = [f["id"] for f in findings if f["id"] not in reviewed_ids]
    if unreviewed:
        return (
            f"Skeptic must review all confirmed medium+ findings. "
            f"Unreviewed: {unreviewed[:5]} (and "
            f"{max(0, len(unreviewed)-5)} more)."
        )
    return None


def _check_orchestrator_global(kg) -> str | None:
    """End-of-scan global gates: all findings need minimal repros, and
    skeptic must have reviewed everything ≥ medium.
    """
    lacking = kg.findings_lacking_minimal_repros()
    if lacking:
        return (
            f"Cannot terminate: {len(lacking)} findings lack a minimal_repro. "
            f"First five: {lacking[:5]}"
        )
    return _check_skeptic(kg)


def _check_chain_builder(kg) -> str | None:
    unexplored = kg.unexplored_primitive_count()
    if unexplored > 0:
        return (
            f"Chain builder has {unexplored} primitives not yet explored for "
            f"chain composition. Continue searching."
        )
    return None


def main() -> int:
    raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}
    agent = hook_input.get("agent", "unknown")
    args = hook_input.get("agent_args", {}) or {}

    kg = open_kg()
    try:
        block_reason: str | None = None
        if agent == "recon":
            block_reason = _check_recon(kg)
        elif agent.startswith("hunter-"):
            block_reason = _check_hunter(kg, agent)
        elif agent == "validator":
            block_reason = _check_validator(kg, args.get("hypothesis_id"))
        elif agent == "chain-builder":
            block_reason = _check_chain_builder(kg)
        elif agent == "skeptic":
            # Skeptic always allowed to stop — its work is per-finding;
            # the global orchestrator check enforces complete coverage.
            block_reason = None
        elif agent in ("orchestrator", "main", "claude"):
            # The top-level orchestrator. Apply the final global gates.
            block_reason = _check_orchestrator_global(kg)

        if block_reason:
            kg.append_event(agent, "subagent_stop_blocked",
                            {"reason": block_reason})
            print(json.dumps({"decision": "block", "reason": block_reason}))
            return 0

        kg.append_event(agent, "subagent_stop_allowed", {})
    finally:
        kg.close()

    print(json.dumps({"decision": "allow"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
