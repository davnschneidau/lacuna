#!/usr/bin/env python3
"""
Stop hook — blocks the orchestrator from declaring itself done until exit
criteria are met in the KG.

This is what makes Lacuna an autonomous scanner rather than a chat session
that happens to scan. Without this hook, the model decides when it's done.
With this hook, the *system* decides, against criteria written to the KG.

Returns:
    {"decision": "allow"}  — exit criteria met, stop permitted
    {"decision": "block", "reason": "<why>; continue from there."}  — keep going
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.hooks import is_orchestrator
from lacuna.kg import open_kg


def main() -> int:
    raw = sys.stdin.read()
    try:
        hook_input = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        hook_input = {}

    agent = hook_input.get("agent", "orchestrator")

    # Subagents are allowed to stop freely — only the orchestrator is bound by
    # exit criteria.
    if not is_orchestrator(agent):
        print(json.dumps({"decision": "allow"}))
        return 0

    kg = open_kg()
    all_met, unmet = kg.all_exit_criteria_met()

    # Every confirmed finding MUST have at least one adversary verdict
    # before the orchestrator can stop. This makes the disprove-first
    # sweep load-bearing: a scan that forgot to run it can't
    # successfully exit.
    missing_verdicts: list[str] = []
    try:
        missing_verdicts = kg.findings_missing_adversary_verdict()
    except Exception:
        # If the migration hasn't run yet (older KG), don't block —
        # but the migration runs on initialize() so this should only
        # happen during the very first call against an empty DB.
        missing_verdicts = []

    if all_met and not missing_verdicts:
        kg.append_event("orchestrator", "stop_allowed", {})
        kg.close()
        print(json.dumps({"decision": "allow"}))
        return 0

    status = kg.status_summary()
    pending_count = status["hypotheses_pending"] + status["hypotheses_validating"]
    unexplored_prims = status["primitives_unexplored"]

    parts: list[str] = []
    if unmet:
        parts.append(f"Exit criteria not yet met: {', '.join(unmet)}.")
    if pending_count:
        parts.append(
            f"{pending_count} hypotheses still pending or in validation."
        )
    if unexplored_prims:
        parts.append(
            f"{unexplored_prims} primitives have not yet been considered for "
            f"chain composition."
        )
    if "reports_generated" in unmet:
        parts.append(
            "Reports have not been written. Invoke the report-exec and "
            "report-tech skills."
        )
    if missing_verdicts:
        sample = ", ".join(missing_verdicts[:5])
        more = (
            f" (and {len(missing_verdicts) - 5} more)"
            if len(missing_verdicts) > 5 else ""
        )
        parts.append(
            f"{len(missing_verdicts)} confirmed finding(s) have no adversary "
            f"verdict yet: {sample}{more}. Every finding must be reviewed "
            f"by the adversary agent before the scan can stop. Spawn the "
            f"`adversary` subagent on each, then re-attempt the stop."
        )
    parts.append("Continue.")

    reason = " ".join(parts)
    kg.append_event(
        "orchestrator", "stop_blocked",
        {
            "unmet": unmet,
            "missing_verdicts": missing_verdicts,
            "reason": reason,
            "status": status,
        },
    )
    kg.close()

    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
