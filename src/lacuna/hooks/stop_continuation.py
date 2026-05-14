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

    if all_met:
        kg.append_event("orchestrator", "stop_allowed", {})
        kg.close()
        print(json.dumps({"decision": "allow"}))
        return 0

    status = kg.status_summary()
    pending_count = status["hypotheses_pending"] + status["hypotheses_validating"]
    unexplored_prims = status["primitives_unexplored"]

    # Build a directive that tells the orchestrator what's missing.
    parts = [f"Exit criteria not yet met: {', '.join(unmet)}."]
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
    parts.append("Continue.")

    reason = " ".join(parts)
    kg.append_event(
        "orchestrator", "stop_blocked",
        {"unmet": unmet, "reason": reason, "status": status},
    )
    kg.close()

    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
