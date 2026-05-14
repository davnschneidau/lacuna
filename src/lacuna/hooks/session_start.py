#!/usr/bin/env python3
"""
SessionStart hook — initializes the KG, validates the workspace, and writes
the initial scan_started marker.

Idempotent: re-running on the same KG is a no-op (KG is initialized on first
session start; subsequent starts only update meta).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg  # noqa: E402


def main() -> int:
    raw = sys.stdin.read()
    _ = json.loads(raw) if raw.strip() else {}

    kg = open_kg()
    kg.initialize()

    # Write scan metadata if first run
    if kg.get_meta("scan_started_at") is None:
        kg.set_meta("scan_started_at", datetime.now(timezone.utc).isoformat())
        kg.set_meta("scan_mode", os.environ.get("LACUNA_MODE", "sast"))
        kg.set_meta("manifest_path", os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml"))
        kg.set_meta("current_phase", "phase-0-init")
        kg.append_event("system", "scan_started", {
            "mode": os.environ.get("LACUNA_MODE", "sast"),
            "manifest": os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml"),
        })

    # Verify workspace mounts
    workspace = Path("/workspace")
    if not workspace.exists():
        kg.append_event("system", "session_start_warning", {
            "warning": "workspace not mounted at /workspace",
        })

    kg.close()

    # Inject a brief status string into the session
    status_md = (
        "Lacuna session initialized. The KG is at $LACUNA_KG_PATH. "
        "Read /memory/current_phase.md and /memory/application_model.md first."
    )
    print(json.dumps({
        "decision": "allow",
        "additional_context": status_md,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
