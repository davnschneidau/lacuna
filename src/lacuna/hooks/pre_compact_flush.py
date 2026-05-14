#!/usr/bin/env python3
"""
PreCompact hook — runs before Claude Code compacts the transcript.

This is the single most important Lacuna mechanism. Compaction is lossy.
The KG is not. Before any compaction, we scan the transcript for in-flight
reasoning artifacts (hypotheses, primitives, chain candidates, next-actions)
and persist them to the KG.

Agents are taught (via their system prompts and the caveman skill)
to wrap in-flight artifacts in explicit tags:
    <hypothesis-draft>{...}</hypothesis-draft>
    <primitive-draft>{...}</primitive-draft>
    <chain-candidate>{...}</chain-candidate>
    <next-actions>text</next-actions>

The compaction prompt is best-effort. These tags are guaranteed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid

# Make lacuna importable when hook is run from .claude/hooks/
sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg, Hypothesis, Primitive  # noqa: E402

HYP_BLOCK = re.compile(
    r"<hypothesis-draft>\s*(\{.*?\})\s*</hypothesis-draft>", re.DOTALL
)
PRIM_BLOCK = re.compile(
    r"<primitive-draft>\s*(\{.*?\})\s*</primitive-draft>", re.DOTALL
)
CHAIN_BLOCK = re.compile(
    r"<chain-candidate>\s*(\{.*?\})\s*</chain-candidate>", re.DOTALL
)
NEXT_ACTIONS = re.compile(
    r"<next-actions>\s*(.*?)\s*</next-actions>", re.DOTALL
)


def _safe_json(s: str) -> dict | None:
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def main() -> int:
    raw = sys.stdin.read()
    try:
        hook_input = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        hook_input = {}

    transcript = hook_input.get("transcript", "")
    agent_name = hook_input.get("agent", "orchestrator")

    kg = open_kg()
    flushed = {"hypotheses": 0, "primitives": 0, "chains": 0, "actions": 0}

    # 1. In-flight hypotheses
    for match in HYP_BLOCK.finditer(transcript):
        data = _safe_json(match.group(1))
        if not data:
            continue
        try:
            h = Hypothesis(
                id=data.get("id", f"hyp-{uuid.uuid4().hex[:12]}"),
                hunter=data.get("hunter", agent_name),
                shape=data.get("shape", "unknown"),
                repo=data.get("repo"),
                file=data.get("file"),
                line=data.get("line"),
                description=data.get("description", ""),
                attacker_scenario=data.get("attacker_scenario"),
                confidence=float(data.get("confidence", 0.3)),
                status=data.get("status", "pending"),
            )
            kg.add_hypothesis(h)
            flushed["hypotheses"] += 1
        except Exception as e:
            kg.append_event(agent_name, "precompact_flush_error",
                            {"kind": "hypothesis", "error": str(e), "data": data})

    # 2. In-flight primitives (validator emits these as findings confirm)
    for match in PRIM_BLOCK.finditer(transcript):
        data = _safe_json(match.group(1))
        if not data:
            continue
        try:
            p = Primitive(
                id=data.get("id", f"prim-{uuid.uuid4().hex[:12]}"),
                finding_id=data.get("finding_id", ""),
                name=data.get("name", "unnamed"),
                description=data.get("description", ""),
                prerequisites=data.get("prerequisites", []),
                effects=data.get("effects", []),
                repos_involved=data.get("repos_involved", []),
            )
            kg.add_primitive(p)
            flushed["primitives"] += 1
        except Exception as e:
            kg.append_event(agent_name, "precompact_flush_error",
                            {"kind": "primitive", "error": str(e), "data": data})

    # 3. In-flight chain candidates — parked for the chain-builder to resume
    for match in CHAIN_BLOCK.finditer(transcript):
        data = _safe_json(match.group(1))
        if not data:
            continue
        if data.get("status") not in (None, "exploring"):
            continue
        try:
            with kg.tx() as c:
                c.execute(
                    """INSERT OR REPLACE INTO chain_candidates
                       (id, primitive_ids_json, goal, narrative_so_far, status)
                       VALUES (?,?,?,?,?)""",
                    (
                        data.get("id", f"cand-{uuid.uuid4().hex[:12]}"),
                        json.dumps(data.get("primitive_ids", [])),
                        data.get("goal", "unknown"),
                        data.get("narrative_so_far", ""),
                        "exploring",
                    ),
                )
            flushed["chains"] += 1
        except Exception as e:
            kg.append_event(agent_name, "precompact_flush_error",
                            {"kind": "chain", "error": str(e), "data": data})

    # 4. Orchestrator's stated next actions — for re-orientation after compaction
    m = NEXT_ACTIONS.search(transcript)
    if m:
        kg.save_orchestrator_state("next_actions", m.group(1).strip())
        flushed["actions"] = 1

    # 5. Audit the compaction itself
    kg.append_event(
        agent_name,
        "compaction_checkpoint",
        {"phase": "pre", "transcript_bytes": len(transcript), "flushed": flushed},
    )
    kg.close()

    # Always allow the compaction to proceed
    print(json.dumps({"decision": "allow", "flushed": flushed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
