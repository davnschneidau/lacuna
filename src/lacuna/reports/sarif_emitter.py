"""
SARIF 2.1.0 emitter for Lacuna findings.

SARIF is the lingua franca for static-analysis output. Bitbucket, Jira,
GitHub, and most security dashboards know how to consume it. Each Lacuna
finding becomes one SARIF result; each chain becomes a separate "rule" so
that downstream consumers can surface chains distinctly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import __version__
from ..kg import KG

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _rule_id_for(finding: dict) -> str:
    """Derive a stable rule ID for a finding.

    Findings store ``cwes`` as a JSON array (list[str]); using the raw
    list as a ``dict`` key crashes with ``TypeError: unhashable``. We
    normalise to the first CWE (or to the finding ID as a last resort).
    """
    cwes = finding.get("cwes")
    if isinstance(cwes, str):
        try:
            parsed = json.loads(cwes)
            if isinstance(parsed, list) and parsed:
                return str(parsed[0])
        except json.JSONDecodeError:
            return cwes
    elif isinstance(cwes, list) and cwes:
        return str(cwes[0])
    return finding["id"]


def _parse_repos(finding: dict) -> list[str]:
    """``repos_involved`` is a JSON array (sometimes stored as a string)."""
    raw = finding.get("repos_involved")
    if isinstance(raw, list):
        return [str(r) for r in raw if r]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(r) for r in parsed if r]
        except json.JSONDecodeError:
            return [r.strip() for r in raw.split(",") if r.strip()]
    return []


def _load_evidence_payload(e: dict) -> dict | None:
    """Return the structured payload for an evidence row, if any.

    Evidence rows store a ``payload_path`` pointing at a JSON file on
    disk (see ``post_tool_use_record``). Some callers also stash an
    inline ``payload`` dict on the row itself. Try both, preferring
    inline so unit tests can exercise the location-building logic
    without writing files.
    """
    inline = e.get("payload")
    if isinstance(inline, dict):
        return inline
    if isinstance(inline, str):
        try:
            parsed = json.loads(inline)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    path = e.get("payload_path")
    if not path:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _evidence_locations(finding: dict, evidence: list[dict]) -> list[dict]:
    """Build SARIF physicalLocation entries from finding evidence.

    Each evidence row may carry a payload (inline or on disk via
    ``payload_path``) containing ``file`` / ``line``. The previous
    emitter stuffed ``repos_involved`` directly into
    ``artifactLocation.uri`` — which is the wrong shape (a list, not a
    single URI) and produced unusable locations.
    """
    locations: list[dict] = []
    for e in evidence:
        payload = _load_evidence_payload(e)
        if not payload:
            continue
        file_uri = payload.get("file") or payload.get("path")
        if not file_uri:
            continue
        line = payload.get("line")
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": str(file_uri)},
        }
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
        locations.append({"physicalLocation": physical})

    if locations:
        return locations

    repos = _parse_repos(finding)
    if repos:
        return [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"{repos[0]}/"},
            },
        }]
    return [{
        "physicalLocation": {
            "artifactLocation": {"uri": "(unknown)"},
        },
    }]


def _execution_successful(kg: KG) -> bool:
    """The scan was successful iff *every* exit criterion is met."""
    try:
        all_met, _ = kg.all_exit_criteria_met()
    except Exception:
        return False
    return bool(all_met)


def emit_sarif(kg: KG) -> dict[str, Any]:
    findings = kg.list_findings()
    chains = kg.list_chains()

    # Attach adversary verdicts to each SARIF result so downstream
    # ingesters (Bitbucket Pipelines, DefectDojo, Jira) can filter
    # "show me only confirmed findings" vs "show me everything
    # including refute_pending."
    verdicts_by_finding: dict[str, list[dict]] = {}
    try:
        for v in kg.list_adversary_verdicts():
            verdicts_by_finding.setdefault(
                v["finding_id"], [],
            ).append(v)
    except Exception:
        verdicts_by_finding = {}

    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = _rule_id_for(f)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": f["title"][:80],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {
                    "text": (f.get("validator_summary") or "")[:1000],
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF.get(f["severity"], "warning"),
                },
                "properties": {
                    "tags": ["lacuna", "finding", f["severity"]],
                    "security-severity": _security_score(f["severity"]),
                },
            }
        ev = kg.get_evidence(f["id"])
        verdicts = verdicts_by_finding.get(f["id"], [])
        adversary_summary = _summarize_verdicts(verdicts)
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(f["severity"], "warning"),
            "message": {
                "text": f.get("validator_summary") or f["title"],
            },
            "properties": {
                "lacuna_finding_id": f["id"],
                "lacuna_hypothesis_id": f.get("hypothesis_id"),
                "lacuna_repos": _parse_repos(f),
                "lacuna_evidence_paths": [e["payload_path"] for e in ev],
                "lacuna_remediation_md": f.get("remediation_md"),
                "lacuna_scan_kind": f.get("scan_kind"),
                "lacuna_adversary_verdict": adversary_summary["consensus"],
                "lacuna_adversary_verdicts": [
                    {
                        "adversary": v.get("adversary"),
                        "verdict": v.get("verdict"),
                    } for v in verdicts
                ],
            },
            "locations": _evidence_locations(f, ev),
        })

    if chains:
        rules_by_id["LACUNA-CHAIN"] = {
            "id": "LACUNA-CHAIN",
            "name": "Composed Attack Chain",
            "shortDescription": {
                "text": "Multi-step attack composed of confirmed findings.",
            },
            "fullDescription": {
                "text": "Composition of multiple primitives derived from "
                         "confirmed findings, producing a higher-impact "
                         "outcome than any single component.",
            },
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["lacuna", "chain"], "security-severity": "9.0"},
        }
        for c in chains:
            results.append({
                "ruleId": "LACUNA-CHAIN",
                "level": "error",
                "message": {
                    "text": (
                        f"Attack chain → {c.goal}. "
                        f"Composed primitives: {', '.join(c.primitive_ids)}. "
                        + c.narrative_md.split('\n')[0][:300]
                    ),
                },
                "properties": {
                    "lacuna_chain_id": c.id,
                    "lacuna_goal": c.goal,
                    "lacuna_combined_severity": c.combined_severity,
                    "lacuna_primitive_ids": c.primitive_ids,
                    "lacuna_narrative_md": c.narrative_md,
                },
            })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lacuna",
                        "version": __version__,
                        "informationUri":
                            "https://github.com/davnschneidau/lacuna",
                        "rules": list(rules_by_id.values()),
                    },
                },
                "results": results,
                "invocations": [
                    {"executionSuccessful": _execution_successful(kg)},
                ],
            },
        ],
    }


def _security_score(sev: str) -> str:
    return {"critical": "9.5", "high": "7.5",
             "medium": "5.0", "low": "2.0"}.get(sev, "0.0")


def _summarize_verdicts(verdicts: list[dict]) -> dict[str, Any]:
    """Reduce N adversary verdicts to a single SARIF-friendly summary.

    - Empty: ``"refute_pending"`` (because that's the default until any
      adversary runs).
    - One verdict: that verdict.
    - Multiple verdicts that agree: that verdict.
    - Multiple verdicts that disagree: ``"needs_human"`` regardless of
      which one was "right." (Two-adversary mode escalates disagreement
      to a human reviewer rather than picking a winner.)
    """
    if not verdicts:
        return {"consensus": "refute_pending"}
    values = {v.get("verdict") for v in verdicts}
    if len(values) == 1:
        return {"consensus": next(iter(values))}
    return {"consensus": "needs_human"}
