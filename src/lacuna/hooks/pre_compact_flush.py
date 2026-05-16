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

Security note. DAST tool results are attacker-controllable. A target
that echoes ``<hypothesis-draft>{...}</hypothesis-draft>`` in an HTTP
response body, error page, or reflected XSS payload would otherwise be
silently written into the KG as a real hypothesis -- moving
attacker-supplied bytes from the (untrusted) transcript region into a
(trusted) durable knowledge surface. To close that gap, this hook
requires draft tags to appear inside an explicit assistant region
(``<assistant-draft>...</assistant-draft>``) and rejects drafts that
appear inside any of the tool-result regions (``<tool-result>``,
``<dast-response>``, etc.). The agent prompts emit the wrapper; the
recon/DAST tool responses do not.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import Hypothesis, Observation, Primitive, open_kg

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

# Regions that contain *attacker-controlled* bytes. Anything inside one of
# these blocks is untrusted and MUST NOT be promoted into the KG as a draft.
UNTRUSTED_REGIONS = re.compile(
    r"<(?:tool[-_]result|dast[-_]response|http[-_]response|user[-_]message)>"
    r".*?"
    r"</(?:tool[-_]result|dast[-_]response|http[-_]response|user[-_]message)>",
    re.DOTALL,
)

# Regions that contain *agent-authored* bytes. Drafts MUST appear inside
# one of these regions to be promoted. The agent prompts emit the wrapper
# themselves; tools do not.
TRUSTED_REGION = re.compile(
    r"<(?:assistant[-_]draft|agent[-_]reasoning|orchestrator[-_]plan)>"
    r"(.*?)"
    r"</(?:assistant[-_]draft|agent[-_]reasoning|orchestrator[-_]plan)>",
    re.DOTALL,
)


def _safe_json(s: str) -> dict | None:
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def _trusted_transcript(transcript: str) -> str:
    """Return only the assistant-authored regions of the transcript.

    Strategy: extract everything inside a trusted ``<assistant-draft>``
    (or equivalent) block, *then* strip any nested untrusted region
    that may have been quoted into it (e.g. when an agent quotes a
    tool result for citation). The remaining text is the only safe
    surface for promoting drafts into the KG.

    Behaviour for legacy transcripts that don't use trusted wrappers
    is governed by ``LACUNA_PRECOMPACT_REQUIRE_TRUSTED``:

    - ``"1"`` (default) — drop drafts outside any trusted wrapper.
    - ``"0"`` — fall back to the full transcript (legacy behaviour;
      useful for migration of older scans, *not* recommended in DAST
      mode).
    """
    pieces = [m.group(1) for m in TRUSTED_REGION.finditer(transcript)]
    if not pieces:
        if os.environ.get("LACUNA_PRECOMPACT_REQUIRE_TRUSTED", "1") == "0":
            return UNTRUSTED_REGIONS.sub("", transcript)
        return ""
    cleaned = "\n".join(pieces)
    return UNTRUSTED_REGIONS.sub("", cleaned)


def main() -> int:
    raw = sys.stdin.read()
    try:
        hook_input = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        hook_input = {}

    raw_transcript = hook_input.get("transcript", "")
    agent_name = hook_input.get("agent", "orchestrator")
    transcript = _trusted_transcript(raw_transcript)

    kg = open_kg()
    flushed = {
        "hypotheses": 0,
        "primitives": 0,
        "chains": 0,
        "actions": 0,
        "dropped_untrusted": 0,
    }

    # Account for any drafts that *would* have been promoted under the
    # legacy "scan the whole transcript" behaviour but are now refused
    # because they live in an untrusted region. The count is logged so
    # the analyst can see when a target tried to inject drafts.
    untrusted_only = UNTRUSTED_REGIONS.findall(raw_transcript)
    if untrusted_only:
        in_attacker_bytes = "\n".join(untrusted_only)
        for pattern in (HYP_BLOCK, PRIM_BLOCK, CHAIN_BLOCK):
            flushed["dropped_untrusted"] += len(pattern.findall(in_attacker_bytes))

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

    # 3. In-flight chain candidates — parked for the chain-builder to resume.
    # Stored as ``observations`` of kind ``chain_candidate_draft`` so the
    # chain-builder agent finds them through its normal observations API.
    # (Previous versions wrote to a dedicated ``chain_candidates`` table that
    # no agent actually read.)
    for match in CHAIN_BLOCK.finditer(transcript):
        data = _safe_json(match.group(1))
        if not data:
            continue
        if data.get("status") not in (None, "exploring"):
            continue
        try:
            detail = {
                "primitive_ids": data.get("primitive_ids", []),
                "narrative_so_far": data.get("narrative_so_far", ""),
                "draft_id": data.get("id", f"cand-{uuid.uuid4().hex[:12]}"),
            }
            obs = Observation(
                author_agent=agent_name,
                kind="chain_candidate_draft",
                summary=(
                    f"Chain candidate goal={data.get('goal', 'unknown')}"
                    f" prims={len(detail['primitive_ids'])}"
                ),
                detail_md=json.dumps(detail, indent=2),
                affects_shapes=[],
            )
            kg.add_observation(obs)
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
        {
            "phase": "pre",
            "transcript_bytes": len(raw_transcript),
            "trusted_bytes": len(transcript),
            "flushed": flushed,
        },
    )
    if flushed["dropped_untrusted"]:
        kg.append_event(
            agent_name,
            "precompact_injection_attempt",
            {
                "dropped_drafts": flushed["dropped_untrusted"],
                "note": (
                    "Draft tags appeared inside a tool/DAST response region "
                    "and were refused. This is the expected behaviour when an "
                    "attacker-controlled response echoes "
                    "<hypothesis-draft>{...}</hypothesis-draft>."
                ),
            },
        )
    kg.close()

    # Always allow the compaction to proceed
    print(json.dumps({"decision": "allow", "flushed": flushed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
