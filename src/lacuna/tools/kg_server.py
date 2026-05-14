"""
lacuna-kg MCP server.

Exposes the knowledge graph as MCP tools. Agents read findings, hypotheses,
primitives, chains and write new ones through this server. Also exposes the
memory-tool projection of the KG (read/write/list/delete operations on
/memory/... paths).

Tool naming follows MCP convention: flat ``snake_case`` identifiers. The
namespace prefix is encoded in the leading word:

  kg_read_*    → idempotent, side-effect-free
  kg_write_*   → emits an event_log entry
  kg_memory_*  → memory-tool file API backed by the KG

The earlier version used dotted names (``kg.read.application_model``) which
violate the MCP tool-name regex and were silently rejected by some clients.
For backward compatibility ``call_tool`` accepts the legacy names and
forwards them to the snake_case handlers.
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

from lacuna.kg import (
    Chain,
    Finding,
    Hypothesis,
    MemoryAdapter,
    Primitive,
    open_kg,
)

server = Server("lacuna-kg")


def _ok(payload: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload, default=str))]


def _err(msg: str) -> list[TextContent]:
    return _ok({"error": msg})


def _legacy_to_canonical(name: str) -> str:
    """Translate legacy dotted tool names to the canonical snake_case form."""
    if "." in name:
        return name.replace(".", "_")
    return name


# Schemas use an explicit empty ``required`` whenever no field is mandatory,
# so a strict MCP client never has to guess. (The earlier version omitted
# ``required`` on several tools, which trips up validators that treat
# absence as "all properties required".)
_EMPTY_SCHEMA = {"type": "object", "properties": {}, "required": []}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ── read tools ──────────────────────────────────────────────────────
        Tool(name="kg_read_application_model", description=(
            "Read the application model written by recon. Returns the summary "
            "markdown and structured facts. Always call this before forming "
            "hypotheses."
        ), inputSchema=_EMPTY_SCHEMA),

        Tool(name="kg_read_hypotheses", description=(
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

        Tool(name="kg_read_findings", description=(
            "List confirmed findings, optionally filtered by severity."
        ), inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string",
                              "enum": ["low", "medium", "high", "critical"]},
            },
            "required": [],
        }),

        Tool(name="kg_read_primitives", description=(
            "List all primitives. Used by chain-builder."
        ), inputSchema=_EMPTY_SCHEMA),

        Tool(name="kg_read_chains", description=(
            "List discovered attack chains."
        ), inputSchema=_EMPTY_SCHEMA),

        Tool(name="kg_read_evidence", description=(
            "List evidence attached to a finding."
        ), inputSchema={
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        }),

        Tool(name="kg_read_status", description=(
            "Return the high-level scan status summary."
        ), inputSchema=_EMPTY_SCHEMA),

        Tool(name="kg_read_events", description=(
            "Read the most recent N events from the durable event log."
        ), inputSchema={
            "type": "object",
            "properties": {
                "n": {"type": "integer", "default": 50},
                "event_type": {"type": "string"},
            },
            "required": [],
        }),

        Tool(name="kg_read_exit_criteria", description=(
            "Return the exit criteria dictionary. Use to decide whether to stop."
        ), inputSchema=_EMPTY_SCHEMA),

        # ── write tools ─────────────────────────────────────────────────────
        Tool(name="kg_write_application_model", description=(
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

        Tool(name="kg_write_hypothesis", description=(
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

        Tool(name="kg_write_update_hypothesis_status", description=(
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

        Tool(name="kg_write_finding", description=(
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
                "cwes": {"type": "array", "items": {"type": "string"}},
                "repos_involved": {"type": "array",
                                    "items": {"type": "string"}},
                "validator_summary": {"type": "string"},
                "remediation_md": {"type": "string"},
            },
            "required": ["hypothesis_id", "title", "severity",
                         "validator_summary"],
        }),

        Tool(name="kg_write_attach_evidence", description=(
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

        Tool(name="kg_write_primitive", description=(
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

        Tool(name="kg_write_chain", description=(
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

        Tool(name="kg_write_mark_primitive_explored", description=(
            "Mark a primitive as having been considered in chain composition. "
            "When all primitives are explored, the chain-builder is done."
        ), inputSchema={
            "type": "object",
            "properties": {"primitive_id": {"type": "string"}},
            "required": ["primitive_id"],
        }),

        Tool(name="kg_write_set_exit_criterion", description=(
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

        Tool(name="kg_write_event", description=(
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

        Tool(name="kg_write_set_phase", description=(
            "Update the current phase marker."
        ), inputSchema={
            "type": "object",
            "properties": {"phase": {"type": "string"}},
            "required": ["phase"],
        }),

        # ── memory tool projection ──────────────────────────────────────────
        Tool(name="kg_memory_read", description=(
            "Read a file from the memory tree (e.g. /memory/primitives/prim-xyz.md)."
        ), inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }),

        Tool(name="kg_memory_list", description=(
            "List entries at a path (directory-like). E.g. /memory/primitives/."
        ), inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }),

        Tool(name="kg_memory_write", description=(
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
        Tool(name="kg_write_observation", description=(
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

        Tool(name="kg_read_observations", description=(
            "List observations relevant to a hunter. Filter by kind, shape, repo."
        ), inputSchema={
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "shape": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": [],
        }),

        # ─── v2: trust shadow (capability graph) ─────────────────────────────
        Tool(name="kg_write_capability", description=(
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

        Tool(name="kg_write_capability_edge", description=(
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

        Tool(name="kg_read_capability_graph", description=(
            "Read the capability graph (nodes + edges). Paginate with "
            "``page`` and ``page_size`` (default 100, max 1000) to avoid "
            "blowing past the model context window on large graphs."
        ), inputSchema={
            "type": "object",
            "properties": {
                "page": {"type": "integer", "default": 0, "minimum": 0},
                "page_size": {"type": "integer", "default": 100,
                                "minimum": 1, "maximum": 1000},
            },
            "required": [],
        }),

        # ─── v2: weird compositions ──────────────────────────────────────────
        Tool(name="kg_write_weird_composition", description=(
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

        Tool(name="kg_read_weird_compositions", description=(
            "List all weird compositions."
        ), inputSchema=_EMPTY_SCHEMA),

        # ─── v2: minimal repro enforcement ───────────────────────────────────
        Tool(name="kg_write_minimal_repro", description=(
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

        Tool(name="kg_read_minimal_repro", description=(
            "Fetch the minimal repro for a finding."
        ), inputSchema={
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        }),

        Tool(name="kg_read_findings_lacking_repros", description=(
            "List finding IDs that don't yet have a minimal_repro. Stop hook "
            "checks this — scan cannot conclude with unmet repros."
        ), inputSchema=_EMPTY_SCHEMA),

        # ─── v2: coverage gaps ───────────────────────────────────────────────
        Tool(name="kg_write_coverage_gap", description=(
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

        Tool(name="kg_read_coverage_gaps", description=(
            "List all coverage gaps recorded during this scan."
        ), inputSchema=_EMPTY_SCHEMA),

        # ─── v2: gadgets ─────────────────────────────────────────────────────
        Tool(name="kg_read_gadgets", description=(
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
        Tool(name="kg_read_reachability", description=(
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

        Tool(name="kg_read_flow_paths", description=(
            "All taint flow paths persisted from prior data_flow_paths calls."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": [],
        }),

        # ─── v3: precision findings ──────────────────────────────────
        Tool(name="kg_read_precision_findings", description=(
            "Layer 2 precision-analysis findings (integer overflow, UAF, "
            "format string, type confusion). Filter by kind/repo/unconsumed. "
            "These are high-quality leads — hunters convert them into "
            "hypotheses."
        ), inputSchema={
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "repo": {"type": "string"},
                "unconsumed_only": {"type": "boolean", "default": False},
            },
            "required": [],
        }),

        # ─── v3: sanitizer builds ────────────────────────────────────────
        Tool(name="kg_read_sanitizer_builds", description=(
            "Sanitizer-instrumented build records by repo+git_sha. Returns "
            "binaries, warnings caught at compile time, and status."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "git_sha": {"type": "string"},
                "sanitizers": {"type": "string", "default": "asan,ubsan"},
            },
            "required": ["repo", "git_sha"],
        }),

        # ─── v3: fuzz runs and crashes ───────────────────────────────────
        Tool(name="kg_read_fuzz_runs", description=(
            "Fuzz runs for a function. Returns run metadata "
            "(status, executions, coverage)."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "function_qual": {"type": "string"},
            },
            "required": ["repo", "function_qual"],
        }),

        Tool(name="kg_read_fuzz_crashes", description=(
            "Crashes for a fuzz run, with ASan kind, stack frames, and "
            "minimized-input paths."
        ), inputSchema={
            "type": "object",
            "properties": {
                "fuzz_run_id": {"type": "string"},
            },
            "required": ["fuzz_run_id"],
        }),

        # ─── v3: patch rules and variants ────────────────────────────────
        Tool(name="kg_read_patch_rules", description=(
            "Patch-derived rules generated by patch_essence. Filter by "
            "source_kind (internal_commit, cve, finding) and repo."
        ), inputSchema={
            "type": "object",
            "properties": {
                "source_kind": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": [],
        }),

        Tool(name="kg_read_variant_links", description=(
            "Variant findings: child hypotheses spawned from a parent finding "
            "by variant-hunter. Use to group findings into clusters in the "
            "report."
        ), inputSchema={
            "type": "object",
            "properties": {
                "parent_finding_id": {"type": "string"},
            },
            "required": ["parent_finding_id"],
        }),

        Tool(name="kg_write_variant_link", description=(
            "Record that a hypothesis is a variant of a parent finding."
        ), inputSchema={
            "type": "object",
            "properties": {
                "child_hyp_id": {"type": "string"},
                "parent_finding_id": {"type": "string"},
                "propagation_rule_id": {"type": "string"},
            },
            "required": ["child_hyp_id", "parent_finding_id"],
        }),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    name = _legacy_to_canonical(name)
    kg = open_kg()
    try:
        # ── reads ────────────────────────────────────────────────────────────
        if name == "kg_read_application_model":
            am = kg.read_application_model()
            if not am:
                return _ok({"summary": "no application model written yet"})
            return _ok({
                "summary": am["summary_md"][:200] + "…",
                "summary_md": am["summary_md"],
                "facts": am["facts"],
            })
        if name == "kg_read_hypotheses":
            hyps = kg.list_hypotheses(
                status=arguments.get("status"),
                min_confidence=arguments.get("min_confidence"),
            )
            return _ok({
                "summary": f"{len(hyps)} hypotheses",
                "handles": hyps,
            })
        if name == "kg_read_findings":
            findings = kg.list_findings(severity=arguments.get("severity"))
            return _ok({
                "summary": f"{len(findings)} findings",
                "handles": findings,
            })
        if name == "kg_read_primitives":
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
        if name == "kg_read_chains":
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
        if name == "kg_read_evidence":
            ev = kg.get_evidence(arguments["finding_id"])
            return _ok({"summary": f"{len(ev)} evidence", "handles": ev})
        if name == "kg_read_status":
            return _ok(kg.status_summary())
        if name == "kg_read_events":
            return _ok({
                "events": kg.recent_events(
                    n=arguments.get("n", 50),
                    event_type=arguments.get("event_type"),
                ),
            })
        if name == "kg_read_exit_criteria":
            return _ok(kg.exit_criteria_dict())

        # ── writes ───────────────────────────────────────────────────────────
        if name == "kg_write_application_model":
            kg.write_application_model(
                arguments["summary_md"], arguments["facts"],
            )
            return _ok({"ok": True})
        if name == "kg_write_hypothesis":
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
        if name == "kg_write_update_hypothesis_status":
            kg.update_hypothesis_status(
                arguments["hypothesis_id"],
                arguments["status"],
                refutation_reason=arguments.get("refutation_reason"),
            )
            return _ok({"ok": True})
        if name == "kg_write_finding":
            cwes_in = arguments.get("cwes")
            if isinstance(cwes_in, str):
                cwes_list = [c.strip() for c in cwes_in.split(",") if c.strip()]
            else:
                cwes_list = list(cwes_in or [])
            repos_in = arguments.get("repos_involved")
            if isinstance(repos_in, str):
                repos_list = [r.strip() for r in repos_in.split(",") if r.strip()]
            else:
                repos_list = list(repos_in or [])
            f = Finding(
                hypothesis_id=arguments["hypothesis_id"],
                title=arguments["title"],
                severity=arguments["severity"],
                cvss_vector=arguments.get("cvss_vector"),
                cwes=cwes_list,
                repos_involved=repos_list,
                validator_summary=arguments["validator_summary"],
                remediation_md=arguments.get("remediation_md"),
            )
            fid = kg.add_finding(f)
            return _ok({"finding_id": fid})
        if name == "kg_write_attach_evidence":
            kg.attach_evidence(
                arguments["finding_id"],
                arguments["kind"],
                arguments["payload_path"],
            )
            return _ok({"ok": True})
        if name == "kg_write_primitive":
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
        if name == "kg_write_chain":
            c = Chain(
                primitive_ids=arguments["primitive_ids"],
                goal=arguments["goal"],
                combined_severity=arguments.get("combined_severity", "high"),
                narrative_md=arguments["narrative_md"],
            )
            cid = kg.add_chain(c)
            return _ok({"chain_id": cid})
        if name == "kg_write_mark_primitive_explored":
            kg.mark_primitive_explored(arguments["primitive_id"])
            return _ok({"ok": True})
        if name == "kg_write_set_exit_criterion":
            kg.set_exit_criterion(
                arguments["name"], arguments["met"],
                reason=arguments.get("reason"),
            )
            return _ok({"ok": True})
        if name == "kg_write_event":
            eid = kg.append_event(
                arguments["agent"],
                arguments["event_type"],
                arguments.get("payload", {}),
            )
            return _ok({"event_id": eid})
        if name == "kg_write_set_phase":
            kg.set_meta("current_phase", arguments["phase"])
            return _ok({"ok": True})

        # ── memory ───────────────────────────────────────────────────────────
        if name == "kg_memory_read":
            adapter = MemoryAdapter(kg)
            content = adapter.read(arguments["path"])
            if content is None:
                return _err(f"not found: {arguments['path']}")
            return _ok({"path": arguments["path"], "content": content})
        if name == "kg_memory_list":
            adapter = MemoryAdapter(kg)
            return _ok({
                "path": arguments["path"],
                "entries": adapter.list(arguments["path"]),
            })
        if name == "kg_memory_write":
            adapter = MemoryAdapter(kg)
            ok = adapter.write(arguments["path"], arguments["content"])
            if not ok:
                return _err(
                    "writes are only permitted under /memory/agent_notes/"
                )
            return _ok({"ok": True})

        # ── v2: observations ────────────────────────────────────────────────
        if name == "kg_write_observation":
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
        if name == "kg_read_observations":
            rows = kg.list_observations(
                kind=arguments.get("kind"),
                shape=arguments.get("shape"),
                repo=arguments.get("repo"),
            )
            return _ok({"summary": f"{len(rows)} observations",
                          "handles": rows})

        # ── v2: capability graph (trust shadow) ─────────────────────────────
        if name == "kg_write_capability":
            from lacuna.kg import Capability
            cap = Capability(
                asset_kind=arguments["asset_kind"],
                asset_name=arguments["asset_name"],
                holder_repo=arguments["holder_repo"],
                grants=arguments.get("grants", []) or [],
            )
            cid = kg.add_capability(cap)
            return _ok({"id": cid, "summary": "capability recorded"})
        if name == "kg_write_capability_edge":
            kg.add_capability_edge(
                arguments["from_repo"], arguments["to_capability"],
                arguments["relationship"], arguments.get("detail"),
            )
            return _ok({"ok": True})
        if name == "kg_read_capability_graph":
            page = max(0, int(arguments.get("page", 0)))
            page_size = max(1, min(1000, int(arguments.get("page_size", 100))))
            nodes = kg.list_capabilities()
            edges = kg.list_capability_edges()
            ns, ne = len(nodes), len(edges)
            start = page * page_size
            end = start + page_size
            nodes_page = nodes[start:end]
            edges_page = edges[start:end]
            return _ok({
                "summary": (
                    f"capability graph page={page} "
                    f"({len(nodes_page)} of {ns} nodes, "
                    f"{len(edges_page)} of {ne} edges)"
                ),
                "page": page,
                "page_size": page_size,
                "total_nodes": ns,
                "total_edges": ne,
                "more_nodes": end < ns,
                "more_edges": end < ne,
                "nodes": nodes_page,
                "edges": edges_page,
            })

        # ── v2: weird compositions ──────────────────────────────────────────
        if name == "kg_write_weird_composition":
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
        if name == "kg_read_weird_compositions":
            rows = kg.list_weird_compositions()
            return _ok({"summary": f"{len(rows)} compositions",
                          "handles": rows})

        # ── v2: minimal repros ──────────────────────────────────────────────
        if name == "kg_write_minimal_repro":
            kg.set_minimal_repro(
                arguments["finding_id"], arguments["minimal_payload"],
                arguments.get("minimization_steps"),
            )
            return _ok({"ok": True})
        if name == "kg_read_minimal_repro":
            r = kg.get_minimal_repro(arguments["finding_id"])
            if r is None:
                return _err(f"no minimal_repro for {arguments['finding_id']}")
            return _ok(r)
        if name == "kg_read_findings_lacking_repros":
            ids = kg.findings_lacking_minimal_repros()
            return _ok({"summary": f"{len(ids)} findings lack minimal repro",
                          "handles": ids})

        # ── v2: coverage gaps ───────────────────────────────────────────────
        if name == "kg_write_coverage_gap":
            kg.add_coverage_gap(
                arguments["surface"], arguments["reason"],
                arguments.get("suggested_action"),
            )
            return _ok({"ok": True})
        if name == "kg_read_coverage_gaps":
            rows = kg.list_coverage_gaps()
            return _ok({"summary": f"{len(rows)} coverage gaps",
                          "handles": rows})

        # ── v2: gadgets ─────────────────────────────────────────────────────
        if name == "kg_read_gadgets":
            rows = kg.query_gadgets(
                arguments["language"], arguments.get("library"),
            )
            return _ok({"summary": f"{len(rows)} gadgets known",
                          "handles": rows})

        # ── v2: reachability cache ──────────────────────────────────────────
        if name == "kg_read_reachability":
            r = kg.lookup_reachability(
                arguments["repo"], arguments["from_function"],
                arguments["to_function"],
            )
            if r is None:
                return _ok({"cached": False, "summary": "not cached"})
            return _ok({"cached": True, **r})

        if name == "kg_read_flow_paths":
            rows = kg.list_flow_paths(arguments.get("repo"))
            return _ok({"summary": f"{len(rows)} flow paths",
                          "handles": rows})

        # ─── v3 reads ──────────────────────────────────────────────────
        if name == "kg_read_precision_findings":
            rows = kg.list_precision_findings(
                kind=arguments.get("kind"),
                repo=arguments.get("repo"),
                unconsumed_only=arguments.get("unconsumed_only", False),
            )
            return _ok({
                "summary": f"{len(rows)} precision findings",
                "handles": [
                    {
                        "id": r["id"], "kind": r["kind"],
                        "file": r["file"], "line": r["line"],
                        "cwe": r["cwe"], "confidence": r["confidence"],
                        "function_qual": r["function_qual"],
                    } for r in rows[:50]
                ],
                "facets": {
                    k: sum(1 for r in rows if r["kind"] == k)
                    for k in {r["kind"] for r in rows}
                },
            })

        if name == "kg_read_sanitizer_builds":
            row = kg.latest_sanitizer_build(
                repo=arguments["repo"],
                git_sha=arguments["git_sha"],
                sanitizers=arguments.get("sanitizers", "asan,ubsan"),
            )
            if not row:
                return _ok({"summary": "no build recorded"})
            return _ok({
                "summary": f"build status: {row['status']}",
                "result": row,
            })

        if name == "kg_read_fuzz_runs":
            rows = kg.list_fuzz_runs_for_function(
                repo=arguments["repo"],
                function_qual=arguments["function_qual"],
            )
            return _ok({
                "summary": f"{len(rows)} fuzz runs",
                "runs": rows,
            })

        if name == "kg_read_fuzz_crashes":
            rows = kg.list_fuzz_crashes(arguments.get("fuzz_run_id"))
            return _ok({
                "summary": f"{len(rows)} crashes",
                "crashes": rows,
            })

        if name == "kg_read_patch_rules":
            rows = kg.list_patch_rules(
                source_kind=arguments.get("source_kind"),
                repo=arguments.get("repo"),
            )
            return _ok({
                "summary": f"{len(rows)} patch rules",
                "handles": [
                    {
                        "id": r["id"], "bug_class": r["bug_class"],
                        "source_ref": r["source_ref"],
                        "confidence": r["confidence"],
                    } for r in rows[:50]
                ],
            })

        if name == "kg_read_variant_links":
            rows = kg.list_variants_of(arguments["parent_finding_id"])
            return _ok({
                "summary": f"{len(rows)} variants of "
                            f"{arguments['parent_finding_id']}",
                "variants": rows,
            })

        if name == "kg_write_variant_link":
            kg.add_variant_link(
                child_hyp_id=arguments["child_hyp_id"],
                parent_finding_id=arguments["parent_finding_id"],
                propagation_rule_id=arguments.get("propagation_rule_id"),
            )
            return _ok({"summary": "variant link recorded"})

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
