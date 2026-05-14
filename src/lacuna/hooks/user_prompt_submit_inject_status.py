#!/usr/bin/env python3
"""
UserPromptSubmit hook — injects current KG status so the orchestrator
re-orients across compactions and ad-hoc re-engagements.

Runs every time a user message is submitted. The injected content is small
(under ~500 tokens) and lives in Tier 2 of the context model.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg  # noqa: E402


def main() -> int:
    raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}

    kg = open_kg()
    status = kg.status_summary()
    next_actions = kg.latest_orchestrator_state("next_actions") or "(none recorded)"

    am = kg.read_application_model()
    has_model = bool(am)

    lines = [
        "## Current scan status",
        f"- Phase: {status['phase']}",
        f"- Application model loaded: {'yes' if has_model else 'NO (run recon)'}",
        f"- Hypotheses: {status['hypotheses_pending']} pending, "
        f"{status['hypotheses_validating']} validating, "
        f"{status['hypotheses_confirmed']} confirmed, "
        f"{status['hypotheses_refuted']} refuted",
        f"- Findings: {status['findings_critical']} crit / "
        f"{status['findings_high']} high / {status['findings_medium']} med / "
        f"{status['findings_low']} low",
        f"- Primitives: {status['primitives']} total "
        f"({status['primitives_unexplored']} not yet chain-explored)",
        f"- Chains: {status['chains']}",
        f"- Exit criteria: {status['exit_criteria']}",
        "",
        f"### Last recorded next-actions\n{next_actions}",
    ]
    injected = "\n".join(lines)
    kg.close()

    print(json.dumps({"decision": "allow", "additional_context": injected}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
