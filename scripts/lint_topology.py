#!/usr/bin/env python3
"""Validate ``.claude/topology.yaml`` against ``.claude/agents/*.md``.

Every agent the harness can spawn MUST be classified in
``topology.yaml`` as one of:

- ``shared`` (every scan_kind)
- ``sast_only``
- ``dast_only``
- ``either``

And the four lists must be pairwise disjoint.

This script is run in CI on every PR. It exits 1 on any of:

- An agent file exists with no topology entry.
- A topology entry references a missing agent file.
- The same agent appears in two top-level lists.
- A reserved name (orchestrator, system) shows up — those don't have
  agent files because they aren't subagents.

Run locally:

    python scripts/lint_topology.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOPOLOGY_PATH = REPO_ROOT / ".claude" / "topology.yaml"
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"

VALID_CATEGORIES = {"shared", "sast_only", "dast_only", "either"}

# Agents that the harness uses internally; they live in CLAUDE.md / the
# orchestrator prompt rather than as ``.md`` agent files, so we don't
# require an entry for them.
RESERVED_NAMES = {"orchestrator", "system"}


def _load_topology() -> dict:
    import yaml
    with open(TOPOLOGY_PATH) as f:
        return yaml.safe_load(f) or {}


def _agent_names_from_files() -> set[str]:
    names: set[str] = set()
    for p in AGENTS_DIR.glob("*.md"):
        names.add(p.stem)
    return names


def main() -> int:
    if not TOPOLOGY_PATH.exists():
        print(f"ERROR: {TOPOLOGY_PATH} missing", file=sys.stderr)
        return 1
    if not AGENTS_DIR.exists():
        print(f"ERROR: {AGENTS_DIR} missing", file=sys.stderr)
        return 1

    topology = _load_topology()
    errors: list[str] = []

    unknown_categories = set(topology) - VALID_CATEGORIES
    if unknown_categories:
        errors.append(
            f"topology.yaml has unknown top-level keys: "
            f"{sorted(unknown_categories)} (expected subset of {sorted(VALID_CATEGORIES)})"
        )

    classified: dict[str, list[str]] = {}
    for cat in VALID_CATEGORIES:
        for name in topology.get(cat, []) or []:
            classified.setdefault(name, []).append(cat)

    for name, cats in classified.items():
        if len(cats) > 1:
            errors.append(
                f"agent {name!r} appears in multiple categories: {cats}"
            )

    declared = set(classified)
    on_disk = _agent_names_from_files()

    missing_from_topology = sorted((on_disk - declared) - RESERVED_NAMES)
    for name in missing_from_topology:
        errors.append(
            f"agent file .claude/agents/{name}.md is not classified "
            f"in topology.yaml (add to one of: shared / sast_only / "
            f"dast_only / either)"
        )

    missing_from_disk = sorted((declared - on_disk) - RESERVED_NAMES)
    for name in missing_from_disk:
        errors.append(
            f"topology.yaml references agent {name!r} but no "
            f".claude/agents/{name}.md exists"
        )

    if errors:
        print("FAIL: topology lint found problems:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(classified)} agents classified, "
        f"{len(on_disk)} on disk, no conflicts."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
