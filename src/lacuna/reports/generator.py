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

from jinja2 import Environment

from .. import __version__
from ..kg import open_kg
from .sarif_emitter import emit_sarif

# Single source of truth for the report header version.
VERSION = __version__


def _read_template(name: str) -> str:
    return (resources.files("lacuna.reports") / name).read_text()


def _format_duration(
    start_str: str | None, end_str: str | None = None,
) -> str:
    """Format the scan duration.

    Uses ``scan_finished_at`` when available so reports re-generated
    from a finished scan show the same duration on every run. Falls back
    to the current time only if the scan hasn't been marked finished.
    """
    if not start_str:
        return "unknown"
    try:
        start = int(start_str)
    except ValueError:
        return start_str
    if end_str:
        try:
            end = int(end_str)
        except ValueError:
            end = int(time.time())
    else:
        end = int(time.time())
    seconds = max(0, end - start)
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

    scan_kind = kg.get_meta("scan_kind") or "sast"
    scan_scope = kg.get_meta("scan_scope") or "full"
    scan_mode = kg.get_meta("scan_mode") or "sast"
    return {
        "app_name": app_name,
        "scan_date": time.strftime("%Y-%m-%d"),
        "scan_mode": scan_mode,
        "scan_kind": scan_kind,
        "scan_scope": scan_scope,
        "scan_kind_human": (
            "SAST + DAST (static + dynamic)"
            if scan_kind == "sast_dast"
            else "SAST (static analysis only)"
        ),
        "scan_scope_human": (
            "diff-scoped (changed files + transitive imports)"
            if scan_scope == "diff" else "full repository"
        ),
        "repo_count": len(repos),
        "repo_names": repo_names,
        "scan_duration": _format_duration(
            kg.get_meta("scan_started_at"),
            kg.get_meta("scan_finished_at"),
        ),
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
        "scan_duration": _format_duration(
            kg.get_meta("scan_started_at"),
            kg.get_meta("scan_finished_at"),
        ),
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
        "adversary_verdicts": _collect_adversary_verdicts(kg),
        "refuted_appendix": _collect_refuted_findings(kg, findings_full),
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
    """Group findings into parent → children variant clusters.

    The original implementation re-scanned ``kg.list_hypotheses()`` (a
    SQL query that fans out into a Python list) inside a nested loop —
    O(F·H·V). We materialise the hypothesis-by-id index once.
    """
    hypothesis_by_id: dict[str, dict] = {h["id"]: h for h in kg.list_hypotheses()}
    clusters: list[dict] = []
    for f in findings:
        variants = kg.list_variants_of(f["id"])
        if not variants:
            continue
        children: list[dict] = []
        for v in variants:
            hyp = hypothesis_by_id.get(v["child_hyp_id"])
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
    """Hypotheses raised by ``patch-archaeologist`` as "incomplete fix".

    History: an earlier implementation read three columns --
    ``source_hunter``, ``parent_finding_id``, ``cwe`` -- from the
    ``hypotheses`` table. None of them exist in the live schema
    (``src/lacuna/kg/schema.sql``), so the collector silently returned an
    empty list and the "Incomplete Fixes" section of every report was
    permanently blank.

    Today we:

    1. Match on the real ``hunter`` column (not the non-existent
       ``source_hunter``).
    2. Look up per-hypothesis metadata (``parent_commit``, ``cwe``) from
       ``event_log`` events of type ``incomplete_fix_metadata`` that the
       patch-archaeologist agent emits alongside the draft. When the
       event is missing (older scans, or before the agent prompt is
       updated), the collector still surfaces the hypothesis with ``?``
       placeholders rather than swallowing it.
    """
    out: list[dict] = []
    if not all_hyps:
        return out
    metadata_by_hyp = _patch_archaeologist_metadata(kg)
    for h in all_hyps:
        if (h.get("hunter") or "") != "patch-archaeologist":
            continue
        meta = metadata_by_hyp.get(h["id"], {})
        parent_commit = (
            meta.get("parent_commit")
            or meta.get("parent_finding_id")
            or "?"
        )
        out.append({
            "hyp_id": h["id"],
            "location": f"{h.get('file', '?')}:{h.get('line', '?')}",
            "parent_commit_short": (parent_commit or "?")[:10],
            "bug_class": meta.get("cwe") or "?",
            "verdict": h.get("status"),
        })
    return out


def _patch_archaeologist_metadata(kg) -> dict[str, dict]:
    """Index ``incomplete_fix_metadata`` events by ``hyp_id``.

    Patch-archaeologist is expected to emit one such event per draft
    hypothesis so the reporter can associate the CWE and the parent
    commit. Returns ``{}`` when no events exist (older scans).
    """
    by_id: dict[str, dict] = {}
    for e in kg.recent_events(n=1000, event_type="incomplete_fix_metadata"):
        payload = _parse_event_payload(e)
        hyp_id = payload.get("hyp_id") or payload.get("hypothesis_id")
        if hyp_id:
            by_id[hyp_id] = payload
    return by_id


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


_VERDICT_GLYPH = {
    "confirmed": "[\u2713]",
    "downgrade": "[\u25BC]",
    "refuted": "[\u2717]",
    "needs_human": "[?]",
    "refute_pending": "[\u2026]",
}


def _verdict_glyph(verdict: str | None) -> str:
    """Return a short, terminal-safe glyph for a verdict.

    Used in the executive report and the SARIF emitter. ASCII-only so
    Windows consoles don't barf.
    """
    if not verdict:
        return "[ ]"
    return _VERDICT_GLYPH.get(verdict, f"[{verdict[:3]}]")


def _collect_adversary_verdicts(kg) -> list[dict]:
    """Materialise adversary verdicts for the report template.

    Returns one row per (finding, adversary) pair, with the verdict,
    a short reasoning excerpt, and the glyph. The template groups by
    ``finding_id`` if it wants the per-finding two-adversary delta.
    """
    out: list[dict] = []
    try:
        rows = kg.list_adversary_verdicts()
    except Exception:
        return out
    for r in rows:
        out.append({
            "finding_id": r.get("finding_id"),
            "adversary": r.get("adversary"),
            "verdict": r.get("verdict"),
            "glyph": _verdict_glyph(r.get("verdict")),
            "reasoning": (r.get("reasoning") or "")[:240],
            "argument_against": (r.get("argument_against") or "")[:240],
        })
    return out


def _collect_refuted_findings(kg, findings_full: list[dict]) -> list[dict]:
    """Findings whose verdicts ended in ``refuted`` or ``refute_pending``.

    These don't appear in the main catalog (the validator's confirmed
    finding has been refuted by the adversary) but they belong in an
    appendix so the analyst can see the disagreement.
    """
    by_id: dict[str, dict] = {}
    try:
        verdicts = kg.list_adversary_verdicts()
    except Exception:
        return []
    for v in verdicts:
        if v.get("verdict") in ("refuted", "refute_pending"):
            fid = v.get("finding_id")
            if not fid:
                continue
            by_id.setdefault(fid, {
                "finding_id": fid,
                "verdicts": [],
            })["verdicts"].append({
                "adversary": v.get("adversary"),
                "verdict": v.get("verdict"),
                "glyph": _verdict_glyph(v.get("verdict")),
                "reasoning": (v.get("reasoning") or "")[:240],
            })

    findings_by_id = {f["id"]: f for f in findings_full}
    out: list[dict] = []
    for fid, row in by_id.items():
        f = findings_by_id.get(fid, {})
        out.append({
            **row,
            "title": f.get("title", fid),
            "severity": f.get("severity", "?"),
        })
    return out


def _collect_skeptic_reviews(kg) -> list[dict]:
    """Pull skeptic reviews from the events stream.

    History: the original implementation called ``e.get("payload")``
    -- but ``KG.recent_events`` returns rows from the ``event_log``
    table where the payload column is named ``payload_json`` and is a
    JSON *string*, not an already-deserialised dict. The dict-style
    access silently returned ``None`` for every event, so the
    "Skeptic Reviews" section of every report was permanently empty.
    The fix uses ``_parse_event_payload`` to handle both legacy dict
    payloads and the canonical JSON-string format defensively.
    """
    out: list[dict] = []
    for e in kg.recent_events(n=500, event_type="skeptic_review"):
        p = _parse_event_payload(e)
        out.append({
            "finding_id": p.get("finding_id"),
            "verdict": p.get("verdict"),
            "notes": (p.get("reasoning") or "")[:120],
        })
    return out


def _parse_event_payload(e: dict) -> dict:
    """Return the event payload as a dict regardless of column shape.

    ``KG.recent_events`` returns rows from ``event_log``. The canonical
    column is ``payload_json`` (TEXT, stringified JSON). Older code
    paths and a few tests passed a pre-deserialised ``payload`` dict
    directly; we honour both to avoid the report breaking on either.
    Anything we can't parse is logged-by-omission (return ``{}``)
    rather than raising — the reporter must not crash on a single bad
    event.
    """
    raw = e.get("payload_json")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    raw_obj = e.get("payload")
    if isinstance(raw_obj, dict):
        return raw_obj
    if isinstance(raw_obj, str) and raw_obj:
        try:
            parsed = json.loads(raw_obj)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def write_reports(reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    kg = open_kg()
    try:
        # Pin the "scan finished" timestamp once so re-running the
        # generator on a finished scan returns deterministic durations.
        if not kg.get_meta("scan_finished_at"):
            kg.set_meta("scan_finished_at", str(int(time.time())))
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
