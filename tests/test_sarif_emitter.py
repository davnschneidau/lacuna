"""Tests for the SARIF 2.1.0 emitter."""
from __future__ import annotations

import json


def _make_finding_with_hyp(kg, **overrides):
    """Helper: write a hypothesis, then promote it to a finding."""
    from lacuna.kg.client import Finding, Hypothesis
    hyp = Hypothesis(
        hunter="hunter-injection",
        shape="sqli",
        repo="api",
        file="src/db.py",
        line=42,
        description="raw query concat",
        confidence=0.7,
    )
    kg.add_hypothesis(hyp)
    finding_kwargs = {
        "hypothesis_id": hyp.id,
        "title": "SQL injection in /search",
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwes": ["CWE-89"],
        "repos_involved": ["api"],
        "validator_summary": "Confirmed via red/blue dialectic.",
        "remediation_md": "Use parameterized queries.",
    }
    finding_kwargs.update(overrides)
    f = Finding(**finding_kwargs)
    kg.add_finding(f)
    return f


def test_emit_sarif_does_not_crash_on_cwes_list(tmp_kg):
    """Regression: ``cwes`` is stored as a JSON list. Earlier emitter used
    the raw list as a dict key and crashed with ``TypeError: unhashable``.
    """
    from lacuna.reports.sarif_emitter import emit_sarif
    _make_finding_with_hyp(tmp_kg)
    doc = emit_sarif(tmp_kg)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CWE-89"


def test_emit_sarif_physicallocation_from_evidence_payload(tmp_kg, tmp_path):
    """When an evidence payload references a real file/line, the
    emitter must surface it in the SARIF physicalLocation. The fallback
    repo-level URI is only acceptable when no evidence carries a
    file."""
    from lacuna.reports.sarif_emitter import emit_sarif

    f = _make_finding_with_hyp(tmp_kg)
    payload_path = tmp_path / "ev.json"
    payload_path.write_text(json.dumps({
        "file": "api/src/db.py",
        "line": 142,
        "snippet": "cursor.execute(f\"...\")",
    }))
    tmp_kg.attach_evidence(f.id, "code_excerpt", str(payload_path))

    doc = emit_sarif(tmp_kg)
    result = doc["runs"][0]["results"][0]
    assert result["locations"], "result must have at least one location"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "api/src/db.py"
    assert loc["region"]["startLine"] == 142


def test_emit_sarif_falls_back_to_repo_when_no_evidence(tmp_kg):
    """No evidence rows -> the location URI falls back to the repo
    directory, which is still a valid SARIF physicalLocation (consumers
    require at least one)."""
    from lacuna.reports.sarif_emitter import emit_sarif
    _make_finding_with_hyp(tmp_kg)
    doc = emit_sarif(tmp_kg)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].startswith("api")


def test_emit_sarif_driver_uses_dunder_version(tmp_kg):
    """The SARIF driver version must come from ``lacuna.__version__``
    instead of a hand-edited constant."""
    from lacuna import __version__
    from lacuna.reports.sarif_emitter import emit_sarif
    _make_finding_with_hyp(tmp_kg)
    doc = emit_sarif(tmp_kg)
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Lacuna"
    assert driver["version"] == __version__


def test_emit_sarif_execution_successful_reflects_kg_state(tmp_kg):
    """``executionSuccessful`` should be True iff every exit criterion
    is met. Fresh KGs have criteria unmet, so the field must be False."""
    from lacuna.reports.sarif_emitter import emit_sarif
    _make_finding_with_hyp(tmp_kg)
    doc = emit_sarif(tmp_kg)
    invocations = doc["runs"][0]["invocations"]
    assert invocations
    assert invocations[0]["executionSuccessful"] is False
