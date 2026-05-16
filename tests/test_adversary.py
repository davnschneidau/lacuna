"""Adversary machinery regression tests."""
from __future__ import annotations

import os
import json
import subprocess
import sys
import sqlite3
from pathlib import Path

import pytest

from lacuna.kg import Finding, Hypothesis

SRC = Path(__file__).parent.parent / "src"


def _seed_finding(kg, fid: str = "fnd-test-1") -> str:
    hyp = Hypothesis(
        id="hyp-test-1",
        hunter="hunter-injection",
        shape="sqli",
        repo="api",
        file="db.py",
        line=42,
        description="raw query",
        attacker_scenario=None,
        confidence=0.7,
        status="pending",
    )
    kg.add_hypothesis(hyp)
    finding = Finding(
        id=fid,
        hypothesis_id="hyp-test-1",
        title="SQL injection in API",
        severity="high",
        cvss_vector=None,
        cwes=["CWE-89"],
        repos_involved=["api"],
        validator_summary="reachable from POST /search",
        remediation_md="parameterise the query",
    )
    kg.add_finding(finding)
    return fid


# ─── KG client: adversary_verdicts table & queries ──────────────────────────

def test_record_and_list_adversary_verdict(tmp_kg):
    _seed_finding(tmp_kg)
    tmp_kg.record_adversary_verdict(
        finding_id="fnd-test-1",
        adversary="adversary",
        verdict="confirmed",
        argument_for="POC executed against staging",
        argument_against="path may be unreachable from prod",
        reasoning="reachable_from returned a 3-hop path",
        evidence={"reachable_from": "POST /search → db.execute"},
    )
    rows = tmp_kg.list_adversary_verdicts(finding_id="fnd-test-1")
    assert len(rows) == 1
    assert rows[0]["verdict"] == "confirmed"
    assert rows[0]["adversary"] == "adversary"
    assert "reachable_from" in (rows[0]["evidence_json"] or "")


def test_adversary_verdict_constraint_rejects_unknown_verdicts(tmp_kg):
    _seed_finding(tmp_kg)
    with pytest.raises(sqlite3.IntegrityError):
        tmp_kg.record_adversary_verdict(
            finding_id="fnd-test-1",
            adversary="adversary",
            verdict="totally-bogus-verdict",
        )


def test_findings_missing_adversary_verdict_after_seed(tmp_kg):
    _seed_finding(tmp_kg, fid="fnd-a")
    finding2 = Finding(
        id="fnd-b",
        hypothesis_id=None,
        title="another",
        severity="medium",
        cvss_vector=None,
        cwes=["CWE-200"],
        repos_involved=["api"],
        validator_summary="…",
        remediation_md="…",
    )
    tmp_kg.add_finding(finding2)

    missing = tmp_kg.findings_missing_adversary_verdict()
    assert set(missing) == {"fnd-a", "fnd-b"}

    tmp_kg.record_adversary_verdict("fnd-a", "adversary", "confirmed")
    missing = tmp_kg.findings_missing_adversary_verdict()
    assert missing == ["fnd-b"]


def test_chain_adversary_verdict_round_trip(tmp_kg):
    tmp_kg.record_chain_adversary_verdict(
        chain_id="chain-1",
        adversary="chain-adversary",
        verdict="downgrade",
        reasoning="step 2 prerequisite mismatch",
    )
    rows = tmp_kg.list_chain_adversary_verdicts(chain_id="chain-1")
    assert len(rows) == 1
    assert rows[0]["verdict"] == "downgrade"


# ─── Stop hook gate ──────────────────────────────────────────────────────────

def _run_hook(module: str, stdin_obj: dict, env: dict) -> dict:
    base_env = {"PATH": os.environ.get("PATH", os.defpath)}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP",
                "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
                "LANG", "LC_ALL", "LC_CTYPE"):
        v = os.environ.get(key)
        if v is not None:
            base_env[key] = v
    child_env = {**base_env, **env, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", module],
        input=json.dumps(stdin_obj),
        capture_output=True, text=True, env=child_env,
    )
    return json.loads(proc.stdout.strip())


def test_stop_hook_blocks_on_missing_adversary_verdicts(tmp_path, monkeypatch):
    """Even if other exit criteria are met, the Stop hook must block
    until every finding has a verdict."""
    kg_path = tmp_path / "kg.db"
    monkeypatch.setenv("LACUNA_KG_PATH", str(kg_path))
    env = {
        "LACUNA_KG_PATH": str(kg_path),
        "LACUNA_SRC_ROOT": str(SRC),
    }
    _run_hook("lacuna.hooks.session_start", {}, env)

    # Seed a finding without a verdict.
    from lacuna.kg import open_kg
    kg = open_kg()
    try:
        _seed_finding(kg)
        # Mark every exit criterion met so the only thing left is the
        # adversary check.
        for crit in kg.exit_criteria_dict():
            kg.set_exit_criterion(crit, met=True)
    finally:
        kg.close()

    result = _run_hook(
        "lacuna.hooks.stop_continuation",
        {"agent": "orchestrator"}, env,
    )
    assert result["decision"] == "block"
    assert "adversary verdict" in result["reason"]
    assert "fnd-test-1" in result["reason"]


def test_stop_hook_allows_once_every_finding_has_a_verdict(tmp_path, monkeypatch):
    kg_path = tmp_path / "kg.db"
    monkeypatch.setenv("LACUNA_KG_PATH", str(kg_path))
    env = {
        "LACUNA_KG_PATH": str(kg_path),
        "LACUNA_SRC_ROOT": str(SRC),
    }
    _run_hook("lacuna.hooks.session_start", {}, env)

    from lacuna.kg import open_kg
    kg = open_kg()
    try:
        _seed_finding(kg)
        for crit in kg.exit_criteria_dict():
            kg.set_exit_criterion(crit, met=True)
        kg.record_adversary_verdict(
            "fnd-test-1", "adversary", "confirmed",
            reasoning="ran disprove-first, no counter-evidence found",
        )
    finally:
        kg.close()

    result = _run_hook(
        "lacuna.hooks.stop_continuation",
        {"agent": "orchestrator"}, env,
    )
    assert result["decision"] == "allow"


# ─── Report rendering & SARIF ───────────────────────────────────────────────

def test_collect_adversary_verdicts_glyphs_and_excerpts(tmp_kg):
    from lacuna.reports.generator import _collect_adversary_verdicts

    _seed_finding(tmp_kg)
    tmp_kg.record_adversary_verdict(
        "fnd-test-1", "adversary", "confirmed", reasoning="ok",
    )
    tmp_kg.record_adversary_verdict(
        "fnd-test-1", "adversary-b", "refuted",
        reasoning="missing sanitizer claim is wrong",
    )
    rows = _collect_adversary_verdicts(tmp_kg)
    assert len(rows) == 2
    verdicts = {(r["adversary"], r["verdict"]) for r in rows}
    assert ("adversary", "confirmed") in verdicts
    assert ("adversary-b", "refuted") in verdicts
    for r in rows:
        assert r["glyph"].startswith("[")


def test_summarize_verdicts_two_adversaries_disagreeing_becomes_needs_human():
    from lacuna.reports.sarif_emitter import _summarize_verdicts
    assert _summarize_verdicts([]) == {"consensus": "refute_pending"}
    assert _summarize_verdicts([
        {"adversary": "a", "verdict": "confirmed"}
    ]) == {"consensus": "confirmed"}
    assert _summarize_verdicts([
        {"adversary": "a", "verdict": "confirmed"},
        {"adversary": "b", "verdict": "confirmed"},
    ]) == {"consensus": "confirmed"}
    assert _summarize_verdicts([
        {"adversary": "a", "verdict": "confirmed"},
        {"adversary": "b", "verdict": "refuted"},
    ]) == {"consensus": "needs_human"}


def test_sarif_emitter_attaches_adversary_verdict_property(tmp_kg):
    from lacuna.reports.sarif_emitter import emit_sarif
    _seed_finding(tmp_kg)
    tmp_kg.record_adversary_verdict(
        "fnd-test-1", "adversary", "confirmed",
    )
    tmp_kg.record_adversary_verdict(
        "fnd-test-1", "adversary-b", "refuted",
    )
    sarif = emit_sarif(tmp_kg)
    result = sarif["runs"][0]["results"][0]
    props = result["properties"]
    assert props["lacuna_adversary_verdict"] == "needs_human"
    advs = {av["adversary"] for av in props["lacuna_adversary_verdicts"]}
    assert advs == {"adversary", "adversary-b"}


def test_refuted_appendix_includes_refuted_findings(tmp_kg):
    from lacuna.reports.generator import (
        _collect_refuted_findings, _verdict_glyph,
    )
    _seed_finding(tmp_kg)
    tmp_kg.record_adversary_verdict(
        "fnd-test-1", "adversary", "refuted",
        reasoning="reachable_from returned no path",
    )
    findings_full = [
        {
            "id": "fnd-test-1",
            "title": "SQL injection in API",
            "severity": "high",
        }
    ]
    appendix = _collect_refuted_findings(tmp_kg, findings_full)
    assert len(appendix) == 1
    assert appendix[0]["finding_id"] == "fnd-test-1"
    assert appendix[0]["title"] == "SQL injection in API"
    assert appendix[0]["verdicts"][0]["glyph"] == _verdict_glyph("refuted")
