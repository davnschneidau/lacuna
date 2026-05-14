"""
Report generator.

Reads the KG and emits:
  - executive-report.md  (narrative; bottom-line; chains-first)
  - technical-report.md  (full finding catalog with evidence)
  - findings.sarif       (SARIF 2.1.0; for Bitbucket/Jira/GitHub ingestion)
  - chains.json          (machine-readable chain catalog)

If the KG indicates the run finished cleanly, all four are written. If the
run was cut short by wall-clock, reports are still written with whatever
state was reached.
"""
from __future__ import annotations

import json
import os
import time
from importlib import resources
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from ..kg import open_kg
from .sarif_emitter import emit_sarif

VERSION = "3.0.0"


def _read_template(name: str) -> str:
    return (resources.files("lacuna.reports") / name).read_text()


def _format_duration(start_str: str | None) -> str:
    if not start_str:
        return "unknown"
    try:
        start = int(start_str)
    except ValueError:
        return start_str
    seconds = int(time.time()) - start
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def _exec_context(kg) -> dict[str, Any]:
    findings = kg.list_findings()
    chains = kg.list_chains()
    primitives_by_id = {p.id: p for p in kg.list_primitives()}
    status = kg.status_summary()
    am = kg.read_application_model() or {}
    app_name = (am.get("facts", {}) or {}).get("application_name") \
                  or kg.get_meta("application_name") or "Unknown"

    crit_high = status["findings_critical"] + status["findings_high"]
    if crit_high == 0 and not chains:
        bottom_line = (
            "**No critical or high-severity findings were identified.** This "
            "is a useful baseline; the scan still produced lower-severity "
            "findings worth reviewing before they age into risk."
        )
    elif chains:
        worst = max(chains, key=lambda c: ["low", "medium", "high", "critical"].index(c.combined_severity))
        bottom_line = (
            f"**This scan identified {len(chains)} multi-step attack chain(s), "
            f"the most severe being '{worst.goal}'.** Chains compose lower-"
            f"severity flaws into outcomes that individually-rated findings "
            f"understate. Address them in the order shown below."
        )
    else:
        bottom_line = (
            f"**This scan identified {status['findings_critical']} critical and "
            f"{status['findings_high']} high-severity findings.** No multi-step "
            f"chains were composed within this scan's budget. Treat the "
            f"individual findings as upper-bound risks pending manual chaining."
        )

    # Repo count
    repos = []
    facts = am.get("facts", {}) or {}
    if "repos" in facts:
        repos = facts["repos"]
    elif "service_map" in facts and "nodes" in facts["service_map"]:
        repos = [n.get("name") for n in facts["service_map"]["nodes"] if n.get("name")]

    # Attacker narrative
    if chains:
        attacker_narrative = "\n\n".join(
            f"**Chain {i+1}** — {c.narrative_md.split(chr(10))[0][:300]}"
            for i, c in enumerate(chains[:3])
        )
    elif crit_high:
        top = [f for f in findings if f["severity"] in ("critical", "high")][:3]
        attacker_narrative = "\n\n".join(
            f"**{f['title']}** — {f['validator_summary'][:300]}"
            for f in top
        )
    else:
        attacker_narrative = (
            "No high-impact attack scenarios were directly confirmed. The "
            "lower-severity findings in the technical report represent the "
            "current attack surface."
        )

    # Priorities
    priorities = []
    for c in chains[:3]:
        priorities.append({
            "title": f"Break the chain to {c.goal}",
            "rationale": (
                f"Eliminating any primitive in this chain "
                f"({', '.join(c.primitive_ids[:3])}…) breaks the path. "
                f"The cheapest link is often the right place to fix first."
            ),
        })
    for f in [f for f in findings if f["severity"] == "critical"][:5]:
        priorities.append({
            "title": f"Remediate: {f['title']}",
            "rationale": f"Critical-severity. Affects {f['repos_involved']}.",
        })
    if not priorities:
        priorities = [{
            "title": "Address medium/low findings before they age",
            "rationale": "Even without immediate critical risk, residual "
                         "findings accrete. Triage the technical report.",
        }]

    repo_names = ", ".join(r for r in repos if isinstance(r, str)) or "(see manifest)"

    return {
        "app_name": app_name,
        "scan_date": time.strftime("%Y-%m-%d"),
        "scan_mode": kg.get_meta("scan_mode") or "sast",
        "repo_count": len(repos),
        "repo_names": repo_names,
        "scan_duration": _format_duration(kg.get_meta("scan_started_at")),
        "bottom_line": bottom_line,
        "critical_count": status["findings_critical"],
        "high_count": status["findings_high"],
        "medium_count": status["findings_medium"],
        "low_count": status["findings_low"],
        "chains": [
            {
                "goal": c.goal,
                "combined_severity": c.combined_severity,
                "primitive_names": ", ".join(
                    primitives_by_id[p].name for p in c.primitive_ids
                    if p in primitives_by_id
                ),
                "narrative_md": c.narrative_md,
            }
            for c in chains
        ],
        "attacker_narrative": attacker_narrative,
        "priorities": priorities,
        "version": VERSION,
    }


def _tech_context(kg) -> dict[str, Any]:
    findings = kg.list_findings()
    chains = kg.list_chains()
    primitives = kg.list_primitives()
    all_hyps = kg.list_hypotheses()
    am = kg.read_application_model() or {}
    status = kg.status_summary()
    app_name = (am.get("facts", {}) or {}).get("application_name") \
                  or kg.get_meta("application_name") or "Unknown"

    # Attach evidence to each finding
    findings_full: list[dict] = []
    for f in findings:
        ev = kg.get_evidence(f["id"])
        findings_full.append({
            "id": f["id"], "title": f["title"], "severity": f["severity"],
            "cvss_vector": f.get("cvss_vector"), "cwes": f.get("cwes"),
            "repos_involved": f.get("repos_involved"),
            "hypothesis_id": f.get("hypothesis_id"),
            "validator_summary": f.get("validator_summary"),
            "remediation_md": f.get("remediation_md"),
            "evidence": ev,
        })

    return {
        "app_name": app_name,
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_mode": kg.get_meta("scan_mode") or "sast",
        "scan_duration": _format_duration(kg.get_meta("scan_started_at")),
        "manifest_path": kg.get_meta("manifest_path") or "?",
        "application_model_summary": am.get("summary_md", "*(not written)*"),
        "repo_count": len((am.get("facts", {}) or {}).get("repos", []) or []),
        "hyp_total": len(all_hyps),
        "hyp_confirmed": status["hypotheses_confirmed"],
        "hyp_refuted": status["hypotheses_refuted"],
        "hyp_needs_human": len([h for h in all_hyps if h["status"] == "needs_human"]),
        "critical_count": status["findings_critical"],
        "high_count": status["findings_high"],
        "medium_count": status["findings_medium"],
        "low_count": status["findings_low"],
        "primitive_count": len(primitives),
        "chain_count": len(chains),
        "findings": findings_full,
        "primitives": [
            {
                "id": p.id, "name": p.name, "description": p.description,
                "prerequisites": p.prerequisites, "effects": p.effects,
                "repos_involved": p.repos_involved, "finding_id": p.finding_id,
            }
            for p in primitives
        ],
        "chains": [
            {
                "id": c.id, "goal": c.goal,
                "combined_severity": c.combined_severity,
                "primitive_ids": c.primitive_ids,
                "narrative_md": c.narrative_md,
            }
            for c in chains
        ],
        "refuted": [h for h in all_hyps if h["status"] == "refuted"],
        "needs_human": [h for h in all_hyps if h["status"] == "needs_human"],
        # ─── v2 additions ─────────────────────────────────────────────────
        "coverage_gaps": kg.list_coverage_gaps(),
        "trust_shadow_summary": kg.get_meta("trust_shadow_summary"),
        "cross_repo_trust_paths": [
            {
                "from_repo": e.get("from_repo"),
                "relationship": e.get("relationship"),
                "to_holder": _find_capability_holder(
                    kg, e.get("to_capability"),
                ),
                "asset": _find_capability_name(
                    kg, e.get("to_capability"),
                ),
            }
            for e in kg.list_capability_edges()
        ][:50],
        "trust_holes": [
            {
                "summary": o["summary"],
                "affects_shapes": o.get("affects_shapes", ""),
            }
            for o in kg.list_observations(kind="trust_boundary_hole")
        ],
        "weird_compositions": kg.list_weird_compositions(),
        "skeptic_reviews": _collect_skeptic_reviews(kg),
        "observations": [
            {
                "kind": o["kind"], "summary": o["summary"],
                "affects_shapes": o.get("affects_shapes", ""),
            }
            for o in kg.list_observations()
            if o["kind"] not in ("trust_boundary_hole",)
        ][:100],
        # ─── v3 additions ─────────────────────────────────────────────────
        "variant_clusters": _collect_variant_clusters(kg, findings_full),
        "crash_reproductions": _collect_crash_reproductions(kg, findings_full),
        "incomplete_fixes": _collect_incomplete_fixes(kg, all_hyps),
        "precision_findings_summary": _summarize_precision_findings(kg),
        "version": VERSION,
        "kg_path": os.environ.get("LACUNA_KG_PATH", "/state/lacuna.db"),
    }


# ─── v3 report-section helpers ─────────────────────────────────────────────

def _collect_variant_clusters(kg, findings: list[dict]) -> list[dict]:
    """Group findings into parent → children variant clusters."""
    clusters: list[dict] = []
    for f in findings:
        variants = kg.list_variants_of(f["id"])
        if not variants:
            continue
        # Resolve child hypothesis locations
        children: list[dict] = []
        for v in variants:
            hyp = next(
                (h for h in kg.list_hypotheses()
                 if h["id"] == v["child_hyp_id"]),
                None,
            )
            if hyp:
                children.append({
                    "hyp_id": v["child_hyp_id"],
                    "location": f"{hyp.get('file', '?')}:{hyp.get('line', '?')}",
                    "verdict": hyp.get("status"),
                })
        if children:
            clusters.append({
                "parent_finding_id": f["id"],
                "parent_title": f["title"],
                "parent_location": _finding_location(f),
                "cwe": (f.get("cwes") or ["?"])[0]
                          if isinstance(f.get("cwes"), list) else "?",
                "children": children,
            })
    return clusters


def _collect_crash_reproductions(
    kg, findings: list[dict],
) -> list[dict]:
    """For each finding with attached fuzz evidence, surface the crash."""
    out: list[dict] = []
    for f in findings:
        ev = f.get("evidence") or []
        # Find evidence rows whose payload mentions a fuzz_crash
        fuzz_crashes = [
            e for e in ev
            if e.get("kind") in ("fuzz_crash", "asan_report")
            or "asan_kind" in str(e.get("payload", ""))
        ]
        if not fuzz_crashes:
            continue
        for e in fuzz_crashes[:3]:
            payload = e.get("payload") or {}
            if isinstance(payload, str):
                try:
                    import json as _j
                    payload = _j.loads(payload)
                except Exception:
                    payload = {}
            out.append({
                "finding_id": f["id"],
                "function_qual": payload.get("function_qual", "?"),
                "asan_kind": payload.get("asan_kind", "unknown"),
                "fuzz_run_id": payload.get("fuzz_run_id", "?"),
                "executions": payload.get("executions"),
                "duration_s": payload.get("duration_s"),
                "input_path": payload.get("input_path", "?"),
                "minimized_input_path": payload.get("minimized_input_path"),
                "asan_log_path": payload.get("asan_log_path", "?"),
                "crash_stack": payload.get("crash_stack", []),
            })
    return out


def _collect_incomplete_fixes(kg, all_hyps: list[dict]) -> list[dict]:
    """Hypotheses whose source_hunter was patch-archaeologist."""
    out: list[dict] = []
    for h in all_hyps:
        if h.get("source_hunter") not in ("patch-archaeologist",):
            continue
        out.append({
            "hyp_id": h["id"],
            "location": f"{h.get('file', '?')}:{h.get('line', '?')}",
            "parent_commit_short": (h.get("parent_finding_id") or "?")[:10],
            "bug_class": h.get("cwe", "?"),
            "verdict": h.get("status"),
        })
    return out


def _summarize_precision_findings(kg) -> list[dict]:
    """Per-kind summary of precision findings + consumption rate."""
    rows = kg.list_precision_findings()
    from collections import Counter
    by_kind: dict[tuple, int] = Counter()
    consumed_by_kind: dict[tuple, int] = Counter()
    for r in rows:
        key = (r["kind"], r.get("cwe") or "?")
        by_kind[key] += 1
        if r.get("consumed_by_hyp"):
            consumed_by_kind[key] += 1
    return [
        {
            "kind": k[0], "cwe": k[1],
            "count": by_kind[k],
            "consumed": consumed_by_kind.get(k, 0),
        }
        for k in sorted(by_kind, key=lambda x: -by_kind[x])
    ]


def _finding_location(f: dict) -> str:
    """Best-effort location string from a finding's evidence."""
    ev = f.get("evidence") or []
    for e in ev:
        payload = e.get("payload") or {}
        if isinstance(payload, dict) and payload.get("file"):
            return f"{payload['file']}:{payload.get('line', '?')}"
    return "?"


def _find_capability_holder(kg, cap_id: str | None) -> str | None:
    if not cap_id:
        return None
    for c in kg.list_capabilities():
        if c.get("id") == cap_id:
            return c.get("holder_repo")
    return None


def _find_capability_name(kg, cap_id: str | None) -> str | None:
    if not cap_id:
        return None
    for c in kg.list_capabilities():
        if c.get("id") == cap_id:
            return c.get("asset_name")
    return None


def _collect_skeptic_reviews(kg) -> list[dict]:
    """Pull skeptic reviews from the events stream."""
    out = []
    for e in kg.recent_events(n=500, event_type="skeptic_review"):
        p = e.get("payload") or {}
        out.append({
            "finding_id": p.get("finding_id"),
            "verdict": p.get("verdict"),
            "notes": (p.get("reasoning") or "")[:120],
        })
    return out


def write_reports(reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    kg = open_kg()
    try:
        env = Environment(
            keep_trailing_newline=True,
            trim_blocks=False, lstrip_blocks=False,
        )
        exec_tpl = env.from_string(_read_template("exec_template.md"))
        tech_tpl = env.from_string(_read_template("tech_template.md"))

        exec_ctx = _exec_context(kg)
        tech_ctx = _tech_context(kg)

        (reports_dir / "executive-report.md").write_text(exec_tpl.render(**exec_ctx))
        (reports_dir / "technical-report.md").write_text(tech_tpl.render(**tech_ctx))

        # SARIF + chains.json
        sarif = emit_sarif(kg)
        (reports_dir / "findings.sarif").write_text(json.dumps(sarif, indent=2))
        (reports_dir / "chains.json").write_text(json.dumps(
            [
                {
                    "id": c.id, "goal": c.goal,
                    "combined_severity": c.combined_severity,
                    "primitive_ids": c.primitive_ids,
                    "narrative_md": c.narrative_md,
                }
                for c in kg.list_chains()
            ],
            indent=2,
        ))

        kg.set_exit_criterion("reports_generated", met=True)
        kg.append_event("harness", "reports_written", {
            "files": ["executive-report.md", "technical-report.md",
                       "findings.sarif", "chains.json"],
        })
    finally:
        kg.close()
