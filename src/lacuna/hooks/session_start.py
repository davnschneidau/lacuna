#!/usr/bin/env python3
"""
SessionStart hook — initializes the KG, validates the workspace, and writes
the initial scan_started marker.

Also seeds the known-gadget catalog so Phase-0 doesn't need a manual
``python3 -c "from lacuna.tools.gadget_catalog import seed_into_kg; ..."``
step (which CLAUDE.md historically called for and the orchestrator
silently forgot).

Idempotent: re-running on the same KG is a no-op (KG is initialized on first
session start; subsequent starts only update meta).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg


def main() -> int:
    raw = sys.stdin.read()
    _ = json.loads(raw) if raw.strip() else {}

    kg = open_kg()
    kg.initialize()

    seeded_gadgets: int | None = None
    if kg.get_meta("scan_started_at") is None:
        kg.set_meta("scan_started_at", datetime.now(UTC).isoformat())
        kg.set_meta("scan_mode", os.environ.get("LACUNA_MODE", "sast"))
        kg.set_meta("manifest_path", os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml"))
        kg.set_meta("current_phase", "phase-0-init")
        kg.append_event("system", "scan_started", {
            "mode": os.environ.get("LACUNA_MODE", "sast"),
            "manifest": os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml"),
        })

        # Seed the gadget catalog. Idempotent (INSERT OR REPLACE) but we
        # only do it on the first session start to keep the event log
        # uncluttered. Failure is non-fatal — the catalog is an
        # optimisation, not a correctness requirement.
        try:
            from lacuna.tools.gadget_catalog import seed_into_kg
            seeded_gadgets = seed_into_kg()
            kg.append_event("system", "gadget_catalog_seeded", {
                "count": seeded_gadgets,
            })
        except Exception as e:
            kg.append_event("system", "gadget_catalog_seed_failed", {
                "error": str(e)[:300],
            })

    workspace = Path(os.environ.get("LACUNA_WORKSPACE", "/workspace"))
    if not workspace.exists():
        kg.append_event("system", "session_start_warning", {
            "warning": f"workspace not mounted at {workspace}",
        })

    kg.close()

    status_md = (
        "Lacuna session initialized. The KG is at $LACUNA_KG_PATH. "
        "Read /memory/current_phase.md and /memory/application_model.md first."
    )
    if seeded_gadgets is not None:
        status_md += f" {seeded_gadgets} gadgets seeded."
    print(json.dumps({
        "decision": "allow",
        "additional_context": status_md,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
