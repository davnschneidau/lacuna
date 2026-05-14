"""
lacuna-kg MCP server.

Exposes the knowledge graph as MCP tools. Agents read findings, hypotheses,
primitives, chains and write new ones through this server. Also exposes the
memory-tool projection of the KG (read/write/list/delete operations on
/memory/... paths).

Tools follow strict shape rules:
  kg.read.*    → idempotent, side-effect-free
  kg.write.*   → emits an event_log entry
  kg.memory.*  → memory-tool file API backed by the KG

Tool naming is dot-separated so namespacing is visible in transcripts.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import (  # noqa: E402
    KG, Chain, Finding, Hypothesis, MemoryAdapter, Primitive, open_kg,
)

server = Server("lacuna-kg")


def _ok(payload: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload, default=str))]


def _err(msg: str) -> list[TextContent]:
    return _ok({"error": msg})


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ── read tools ───────────────────────────────────────────────────────
        Tool(name="kg.read.application_model", description=(
            "Read the application model written by recon. Returns the summary "
            "markdown and structured facts. Always call this before forming "
            "hypotheses."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="kg.read.hypotheses", description=(
            "List hypotheses, filtered by status and minimum confidence."
        ), inputSchema={
            "type": "object",
            "properties": {
                "status": {"type": "string",
                            "enum": ["pending", "validating", "confirmed",
                                     "refuted", "needs_human"]},
                "min_confidence": {"type": "number"},
            },
            "required": [],
        }),

        Tool(name="kg.read.findings", description=(
            "List confirmed findings, optionally filtered by severity."
        ), inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string",
                              "enum": ["low", "medium", "high", "critical"]},
            },
            "required": [],
        }),

        Tool(name="kg.read.primitives", description=(
            "List all primitives. Used by chain-builder."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="kg.read.chains", description=(
            "List discovered attack chains."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="kg.read.evidence", description=(
            "List evidence attached to a finding."
        ), inputSchema={
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        }),

        Tool(name="kg.read.status", description=(
            "Return the high-level scan status summary."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="kg.read.events", description=(
            "Read the most recent N events from the durable event log."
        ), inputSchema={
            "type": "object",
            "properties": {
                "n": {"type": "integer", "default": 50},
                "event_type": {"type": "string"},
            },
            "required": [],
        }),

        Tool(name="kg.read.exit_criteria", description=(
            "Return the exit criteria dictionary. Use to decide whether to stop."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        # ── write tools ──────────────────────────────────────────────────────
        Tool(name="kg.write.application_model", description=(
            "Recon writes the application model here. Fuses repo inventory, "
            "service map, dependencies, secrets, IaC issues, hotspots, "
            "frameworks, and footguns."
        ), inputSchema={
            "type": "object",
            "properties": {
                "summary_md": {"type": "string"},
                "facts": {"type": "object"},
            },
            "required": ["summary_md", "facts"],
        }),

        Tool(name="kg.write.hypothesis", description=(
            "Hunter agents write hypotheses here. Auto-deduplicates against "
            "existing hypotheses at the same file:line±5."
        ), inputSchema={
            "type": "object",
            "properties": {
                "hunter": {"type": "string"},
                "shape": {"type": "string"},
                "repo": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "description": {"type": "string"},
                "attacker_scenario": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["hunter", "shape", "description", "confidence"],
        }),

        Tool(name="kg.write.update_hypothesis_status", description=(
            "Validator updates a hypothesis to confirmed/refuted/needs_human."
        ), inputSchema={
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
                "status": {"type": "string",
                            "enum": ["validating", "confirmed", "refuted",
                                     "needs_human"]},
                "refutation_reason": {"type": "string"},
            },
            "required": ["hypothesis_id", "status"],
        }),

        Tool(name="kg.write.finding", description=(
            "Validator promotes a confirmed hypothesis to a finding. Severity, "
            "CVSS, CWEs, validator_summary, remediation_md required."
        ), inputSchema={
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string",
                              "enum": ["low", "medium", "high", "critical"]},
                "cvss_vector": {"type": "string"},
                "cwes": {"type": "string"},
                "repos_involved": {"type": "string"},
                "validator_summary": {"type": "string"},
                "remediation_md": {"type": "string"},
            },
            "required": ["hypothesis_id", "title", "severity",
                         "validator_summary"],
        }),

        Tool(name="kg.write.attach_evidence", description=(
            "Attach an evidence artifact to a finding."
        ), inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "kind": {"type": "string"},
                "payload_path": {"type": "string"},
            },
            "required": ["finding_id", "kind", "payload_path"],
        }),

        Tool(name="kg.write.primitive", description=(
            "Record an attacker primitive derived from a confirmed finding."
        ), inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "prerequisites": {"type": "array",
                                   "items": {"type": "string"}},
                "effects": {"type": "array", "items": {"type": "string"}},
                "repos_involved": {"type": "array",
                                    "items": {"type": "string"}},
            },
            "required": ["finding_id", "name", "description"],
        }),

        Tool(name="kg.write.chain", description=(
            "Record a confirmed attack chain composed of primitives."
        ), inputSchema={
            "type": "object",
            "properties": {
                "primitive_ids": {"type": "array",
                                   "items": {"type": "string"}},
                "goal": {"type": "string"},
                "combined_severity": {"type": "string"},
                "narrative_md": {"type": "string"},
            },
            "required": ["primitive_ids", "goal", "narrative_md"],
        }),

        Tool(name="kg.write.mark_primitive_explored", description=(
            "Mark a primitive as having been considered in chain composition. "
            "When all primitives are explored, the chain-builder is done."
        ), inputSchema={
            "type": "object",
            "properties": {"primitive_id": {"type": "string"}},
            "required": ["primitive_id"],
        }),

        Tool(name="kg.write.set_exit_criterion", description=(
            "Set an exit criterion as met or unmet."
        ), inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "met": {"type": "boolean"},
                "reason": {"type": "string"},
            },
            "required": ["name", "met"],
        }),

        Tool(name="kg.write.event", description=(
            "Append an event to the durable event log."
        ), inputSchema={
            "type": "object",
            "properties": {
                "agent": {"type": "string"},
                "event_type": {"type": "string"},
                "payload": {"type": "object"},
            },
            "required": ["agent", "event_type"],
        }),

        Tool(name="kg.write.set_phase", description=(
            "Update the current phase marker."
        ), inputSchema={
            "type": "object",
            "properties": {"phase": {"type": "string"}},
            "required": ["phase"],
        }),

        # ── memory tool projection ───────────────────────────────────────────
        Tool(name="kg.memory.read", description=(
            "Read a file from the memory tree (e.g. /memory/primitives/prim-xyz.md)."
        ), inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }),

        Tool(name="kg.memory.list", description=(
            "List entries at a path (directory-like). E.g. /memory/primitives/."
        ), inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }),

        Tool(name="kg.memory.write", description=(
            "Write to agent_notes/{agent}/{path}. Only paths under "
            "/memory/agent_notes/ are writable."
        ), inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        }),

        # ─── v2: cross-hunter observations ──────────────────────────────────
        Tool(name="kg.write.observation", description=(
            "Add an observation to the cross-hunter shared board. Use when a "
            "hunter discovers a non-hypothesis fact (sanitizer bypass pattern, "
            "framework quirk, middleware bypass, secret location) that other "
            "hunters might use."
        ), inputSchema={
            "type": "object",
            "properties": {
                "author_agent": {"type": "string"},
                "kind": {"type": "string",
                          "description": "middleware_bypass | sanitizer_bypass | "
                          "framework_quirk | secret_location | trust_boundary_hole | "
                          "shared_state | reachability_fact | library_gadget"},
                "repo": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "summary": {"type": "string"},
                "detail_md": {"type": "string"},
                "affects_shapes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["author_agent", "kind", "summary"],
        }),

        Tool(name="kg.read.observations", description=(
            "List observations relevant to a hunter. Filter by kind, shape, repo."
        ), inputSchema={
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "shape": {"type": "string"},
                "repo": {"type": "string"},
            },
        }),

        # ─── v2: trust shadow (capability graph) ─────────────────────────────
        Tool(name="kg.write.capability", description=(
            "Record a capability: an asset (key/secret/role/cred) and what it "
            "grants. Use during trust-shadow analysis."
        ), inputSchema={
            "type": "object",
            "properties": {
                "asset_kind": {"type": "string"},
                "asset_name": {"type": "string"},
                "holder_repo": {"type": "string"},
                "grants": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["asset_kind", "asset_name", "holder_repo"],
        }),

        Tool(name="kg.write.capability_edge", description=(
            "Record an edge: from_repo {reads|uses|trusts|inherits|signs_for} "
            "to_capability."
        ), inputSchema={
            "type": "object",
            "properties": {
                "from_repo": {"type": "string"},
                "to_capability": {"type": "string"},
                "relationship": {"type": "string"},
                "detail": {"type": "string"},
            },
            "required": ["from_repo", "to_capability", "relationship"],
        }),

        Tool(name="kg.read.capability_graph", description=(
            "Read the full capability graph (nodes + edges)."
        ), inputSchema={"type": "object", "properties": {}}),

        # ─── v2: weird compositions ──────────────────────────────────────────
        Tool(name="kg.write.weird_composition", description=(
            "Record a weird-machine composition: a set of primitives whose "
            "combined behavior enables unintended computation."
        ), inputSchema={
            "type": "object",
            "properties": {
                "primitive_ids": {"type": "array", "items": {"type": "string"}},
                "intended_use": {"type": "string"},
                "unintended_use": {"type": "string"},
                "enables_goal": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["primitive_ids", "unintended_use"],
        }),

        Tool(name="kg.read.weird_compositions", description=(
            "List all weird compositions."
        ), inputSchema={"type": "object", "properties": {}}),

        # ─── v2: minimal repro enforcement ───────────────────────────────────
        Tool(name="kg.write.minimal_repro", description=(
            "After confirming a finding, validators must record the smallest "
            "payload that proves the primitive. Required before scan can stop."
        ), inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "minimal_payload": {"type": "string"},
                "minimization_steps": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["finding_id", "minimal_payload"],
        }),

        Tool(name="kg.read.minimal_repro", description=(
            "Fetch the minimal repro for a finding."
        ), inputSchema={
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        }),

        Tool(name="kg.read.findings_lacking_repros", description=(
            "List finding IDs that don't yet have a minimal_repro. Stop hook "
            "checks this — scan cannot conclude with unmet repros."
        ), inputSchema={"type": "object", "properties": {}}),

        # ─── v2: coverage gaps ───────────────────────────────────────────────
        Tool(name="kg.write.coverage_gap", description=(
            "Record a surface that was NOT examined and why. Goes into the "
            "tech report's 'we did not examine' section."
        ), inputSchema={
            "type": "object",
            "properties": {
                "surface": {"type": "string"},
                "reason": {"type": "string"},
                "suggested_action": {"type": "string"},
            },
            "required": ["surface", "reason"],
        }),

        Tool(name="kg.read.coverage_gaps", description=(
            "List all coverage gaps recorded during this scan."
        ), inputSchema={"type": "object", "properties": {}}),

        # ─── v2: gadgets ─────────────────────────────────────────────────────
        Tool(name="kg.read.gadgets", description=(
            "Query the known-gadget catalog for the language and (optional) library."
        ), inputSchema={
            "type": "object",
            "properties": {
                "language": {"type": "string"},
                "library": {"type": "string"},
            },
            "required": ["language"],
        }),

        # ─── v2: reachability cache ──────────────────────────────────────────
        Tool(name="kg.read.reachability", description=(
            "Cached reachability fact. Returns null if not yet computed."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "from_function": {"type": "string"},
                "to_function": {"type": "string"},
            },
            "required": ["repo", "from_function", "to_function"],
        }),

        Tool(name="kg.read.flow_paths", description=(
            "All taint flow paths persisted from prior data_flow_paths calls."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
        }),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    kg = open_kg()
    try:
        # ── reads ────────────────────────────────────────────────────────────
        if name == "kg.read.application_model":
            am = kg.read_application_model()
            if not am:
                return _ok({"summary": "no application model written yet"})
            return _ok({
                "summary": am["summary_md"][:200] + "…",
                "summary_md": am["summary_md"],
                "facts": am["facts"],
            })
        if name == "kg.read.hypotheses":
            hyps = kg.list_hypotheses(
                status=arguments.get("status"),
                min_confidence=arguments.get("min_confidence"),
            )
            return _ok({
                "summary": f"{len(hyps)} hypotheses",
                "handles": hyps,
            })
        if name == "kg.read.findings":
            findings = kg.list_findings(severity=arguments.get("severity"))
            return _ok({
                "summary": f"{len(findings)} findings",
                "handles": findings,
            })
        if name == "kg.read.primitives":
            prims = kg.list_primitives()
            return _ok({
                "summary": f"{len(prims)} primitives",
                "handles": [
                    {
                        "id": p.id, "name": p.name,
                        "description": p.description,
                        "prerequisites": p.prerequisites,
                        "effects": p.effects,
                        "repos_involved": p.repos_involved,
                        "finding_id": p.finding_id,
                    }
                    for p in prims
                ],
            })
        if name == "kg.read.chains":
            chains = kg.list_chains()
            return _ok({
                "summary": f"{len(chains)} chains",
                "handles": [
                    {
                        "id": c.id, "goal": c.goal,
                        "combined_severity": c.combined_severity,
                        "primitive_ids": c.primitive_ids,
                        "narrative_md": c.narrative_md,
                    }
                    for c in chains
                ],
            })
        if name == "kg.read.evidence":
            ev = kg.get_evidence(arguments["finding_id"])
            return _ok({"summary": f"{len(ev)} evidence", "handles": ev})
        if name == "kg.read.status":
            return _ok(kg.status_summary())
        if name == "kg.read.events":
            return _ok({
                "events": kg.recent_events(
                    n=arguments.get("n", 50),
                    event_type=arguments.get("event_type"),
                ),
            })
        if name == "kg.read.exit_criteria":
            return _ok(kg.exit_criteria_dict())

        # ── writes ───────────────────────────────────────────────────────────
        if name == "kg.write.application_model":
            kg.write_application_model(
                arguments["summary_md"], arguments["facts"],
            )
            return _ok({"ok": True})
        if name == "kg.write.hypothesis":
            h = Hypothesis(
                hunter=arguments["hunter"],
                shape=arguments["shape"],
                repo=arguments.get("repo"),
                file=arguments.get("file"),
                line=arguments.get("line"),
                description=arguments["description"],
                attacker_scenario=arguments.get("attacker_scenario"),
                confidence=float(arguments["confidence"]),
            )
            hid = kg.add_hypothesis(h)
            return _ok({"hypothesis_id": hid})
        if name == "kg.write.update_hypothesis_status":
            kg.update_hypothesis_status(
                arguments["hypothesis_id"],
                arguments["status"],
                refutation_reason=arguments.get("refutation_reason"),
            )
            return _ok({"ok": True})
        if name == "kg.write.finding":
            f = Finding(
                hypothesis_id=arguments["hypothesis_id"],
                title=arguments["title"],
                severity=arguments["severity"],
                cvss_vector=arguments.get("cvss_vector"),
                cwes=arguments.get("cwes"),
                repos_involved=arguments.get("repos_involved", ""),
                validator_summary=arguments["validator_summary"],
                remediation_md=arguments.get("remediation_md"),
            )
            fid = kg.add_finding(f)
            return _ok({"finding_id": fid})
        if name == "kg.write.attach_evidence":
            kg.attach_evidence(
                arguments["finding_id"],
                arguments["kind"],
                arguments["payload_path"],
            )
            return _ok({"ok": True})
        if name == "kg.write.primitive":
            p = Primitive(
                finding_id=arguments["finding_id"],
                name=arguments["name"],
                description=arguments["description"],
                prerequisites=arguments.get("prerequisites", []),
                effects=arguments.get("effects", []),
                repos_involved=arguments.get("repos_involved", []),
            )
            pid = kg.add_primitive(p)
            return _ok({"primitive_id": pid})
        if name == "kg.write.chain":
            c = Chain(
                primitive_ids=arguments["primitive_ids"],
                goal=arguments["goal"],
                combined_severity=arguments.get("combined_severity", "high"),
                narrative_md=arguments["narrative_md"],
            )
            cid = kg.add_chain(c)
            return _ok({"chain_id": cid})
        if name == "kg.write.mark_primitive_explored":
            kg.mark_primitive_explored(arguments["primitive_id"])
            return _ok({"ok": True})
        if name == "kg.write.set_exit_criterion":
            kg.set_exit_criterion(
                arguments["name"], arguments["met"],
                reason=arguments.get("reason"),
            )
            return _ok({"ok": True})
        if name == "kg.write.event":
            eid = kg.append_event(
                arguments["agent"],
                arguments["event_type"],
                arguments.get("payload", {}),
            )
            return _ok({"event_id": eid})
        if name == "kg.write.set_phase":
            kg.set_meta("current_phase", arguments["phase"])
            return _ok({"ok": True})

        # ── memory ───────────────────────────────────────────────────────────
        if name == "kg.memory.read":
            adapter = MemoryAdapter(kg)
            content = adapter.read(arguments["path"])
            if content is None:
                return _err(f"not found: {arguments['path']}")
            return _ok({"path": arguments["path"], "content": content})
        if name == "kg.memory.list":
            adapter = MemoryAdapter(kg)
            return _ok({
                "path": arguments["path"],
                "entries": adapter.list(arguments["path"]),
            })
        if name == "kg.memory.write":
            adapter = MemoryAdapter(kg)
            ok = adapter.write(arguments["path"], arguments["content"])
            if not ok:
                return _err(
                    "writes are only permitted under /memory/agent_notes/"
                )
            return _ok({"ok": True})

        # ── v2: observations ────────────────────────────────────────────────
        if name == "kg.write.observation":
            from lacuna.kg import Observation
            obs = Observation(
                author_agent=arguments["author_agent"],
                kind=arguments["kind"],
                repo=arguments.get("repo"),
                file=arguments.get("file"),
                line=arguments.get("line"),
                summary=arguments["summary"],
                detail_md=arguments.get("detail_md"),
                affects_shapes=arguments.get("affects_shapes", []) or [],
            )
            oid = kg.add_observation(obs)
            return _ok({"id": oid, "summary": "observation recorded"})
        if name == "kg.read.observations":
            rows = kg.list_observations(
                kind=arguments.get("kind"),
                shape=arguments.get("shape"),
                repo=arguments.get("repo"),
            )
            return _ok({"summary": f"{len(rows)} observations",
                          "handles": rows})

        # ── v2: capability graph (trust shadow) ─────────────────────────────
        if name == "kg.write.capability":
            from lacuna.kg import Capability
            cap = Capability(
                asset_kind=arguments["asset_kind"],
                asset_name=arguments["asset_name"],
                holder_repo=arguments["holder_repo"],
                grants=arguments.get("grants", []) or [],
            )
            cid = kg.add_capability(cap)
            return _ok({"id": cid, "summary": "capability recorded"})
        if name == "kg.write.capability_edge":
            kg.add_capability_edge(
                arguments["from_repo"], arguments["to_capability"],
                arguments["relationship"], arguments.get("detail"),
            )
            return _ok({"ok": True})
        if name == "kg.read.capability_graph":
            return _ok({
                "summary": "capability graph",
                "nodes": kg.list_capabilities(),
                "edges": kg.list_capability_edges(),
            })

        # ── v2: weird compositions ──────────────────────────────────────────
        if name == "kg.write.weird_composition":
            from lacuna.kg import WeirdComposition
            w = WeirdComposition(
                primitive_ids=arguments["primitive_ids"],
                intended_use=arguments.get("intended_use", ""),
                unintended_use=arguments["unintended_use"],
                enables_goal=arguments.get("enables_goal", ""),
                confidence=float(arguments.get("confidence", 0.5)),
            )
            wid = kg.add_weird_composition(w)
            return _ok({"id": wid, "summary": "weird composition recorded"})
        if name == "kg.read.weird_compositions":
            rows = kg.list_weird_compositions()
            return _ok({"summary": f"{len(rows)} compositions",
                          "handles": rows})

        # ── v2: minimal repros ──────────────────────────────────────────────
        if name == "kg.write.minimal_repro":
            kg.set_minimal_repro(
                arguments["finding_id"], arguments["minimal_payload"],
                arguments.get("minimization_steps"),
            )
            return _ok({"ok": True})
        if name == "kg.read.minimal_repro":
            r = kg.get_minimal_repro(arguments["finding_id"])
            if r is None:
                return _err(f"no minimal_repro for {arguments['finding_id']}")
            return _ok(r)
        if name == "kg.read.findings_lacking_repros":
            ids = kg.findings_lacking_minimal_repros()
            return _ok({"summary": f"{len(ids)} findings lack minimal repro",
                          "handles": ids})

        # ── v2: coverage gaps ───────────────────────────────────────────────
        if name == "kg.write.coverage_gap":
            kg.add_coverage_gap(
                arguments["surface"], arguments["reason"],
                arguments.get("suggested_action"),
            )
            return _ok({"ok": True})
        if name == "kg.read.coverage_gaps":
            rows = kg.list_coverage_gaps()
            return _ok({"summary": f"{len(rows)} coverage gaps",
                          "handles": rows})

        # ── v2: gadgets ─────────────────────────────────────────────────────
        if name == "kg.read.gadgets":
            rows = kg.query_gadgets(
                arguments["language"], arguments.get("library"),
            )
            return _ok({"summary": f"{len(rows)} gadgets known",
                          "handles": rows})

        # ── v2: reachability cache ──────────────────────────────────────────
        if name == "kg.read.reachability":
            r = kg.lookup_reachability(
                arguments["repo"], arguments["from_function"],
                arguments["to_function"],
            )
            if r is None:
                return _ok({"cached": False, "summary": "not cached"})
            return _ok({"cached": True, **r})

        if name == "kg.read.flow_paths":
            rows = kg.list_flow_paths(arguments.get("repo"))
            return _ok({"summary": f"{len(rows)} flow paths",
                          "handles": rows})

        return _err(f"unknown tool: {name}")
    finally:
        kg.close()


async def _amain() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
