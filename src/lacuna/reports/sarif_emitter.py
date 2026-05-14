"""
SARIF 2.1.0 emitter for Lacuna findings.

SARIF is the lingua franca for static-analysis output. Bitbucket, Jira,
GitHub, and most security dashboards know how to consume it. Each Lacuna
finding becomes one SARIF result; each chain becomes a separate "rule" so
that downstream consumers can surface chains distinctly.
"""
from __future__ import annotations

from typing import Any

from ..kg import KG


SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def emit_sarif(kg: KG) -> dict[str, Any]:
    findings = kg.list_findings()
    chains = kg.list_chains()

    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f.get("cwes") or f["id"]
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
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(f["severity"], "warning"),
            "message": {
                "text": f.get("validator_summary") or f["title"],
            },
            "properties": {
                "lacuna_finding_id": f["id"],
                "lacuna_hypothesis_id": f.get("hypothesis_id"),
                "lacuna_repos": f.get("repos_involved"),
                "lacuna_evidence_paths": [e["payload_path"] for e in ev],
                "lacuna_remediation_md": f.get("remediation_md"),
            },
            "locations": _location_for(f),
        })

    # Add chains as their own meta-rule
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
                        "version": "1.0.0",
                        "informationUri": "https://your-org.example/lacuna",
                        "rules": list(rules_by_id.values()),
                    },
                },
                "results": results,
                "invocations": [
                    {"executionSuccessful": True},
                ],
            },
        ],
    }


def _security_score(sev: str) -> str:
    return {"critical": "9.5", "high": "7.5",
             "medium": "5.0", "low": "2.0"}.get(sev, "0.0")


def _location_for(finding: dict) -> list[dict]:
    # Lacuna findings reference hypothesis location; pull from KG-encoded
    # hypothesis_id if possible — handled by caller, here we provide a stub
    # if no location is encoded in the finding's repos_involved + summary.
    return [{
        "physicalLocation": {
            "artifactLocation": {
                "uri": (finding.get("repos_involved") or "").split(",")[0],
            },
        },
    }]
