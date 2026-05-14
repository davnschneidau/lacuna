"""Tests for the KG client."""
from __future__ import annotations

from lacuna.kg import Finding, Hypothesis, Primitive


def test_initialize_creates_all_tables(tmp_kg):
    # Schema should have created all expected tables
    rows = tmp_kg._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    table_names = {r["name"] for r in rows}
    expected = {
        "event_log", "application_model", "hypotheses", "findings",
        "evidence", "primitives", "chains",
        "exit_criteria", "tool_audit", "agent_notes",
        "orchestrator_state", "scan_meta",
    }
    assert expected.issubset(table_names), (
        f"missing: {expected - table_names}"
    )
    assert "chain_candidates" not in table_names, (
        "chain_candidates was dropped in v3.0; chain drafts now live as "
        "observations(kind=chain_candidate_draft)"
    )


def test_exit_criteria_seeded(tmp_kg):
    rows = tmp_kg._conn.execute(
        "SELECT name, met FROM exit_criteria"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert names == {
        "application_model_ready", "all_hunters_returned",
        "all_hypotheses_resolved", "chain_search_exhausted",
        "reports_generated",
    }
    # All start as 0/false
    assert all(r["met"] == 0 for r in rows)


def test_hypothesis_dedup_same_file_line_range(tmp_kg):
    h1 = Hypothesis(
        hunter="hunter-injection", shape="sqli",
        repo="api", file="db.py", line=42,
        description="raw query interp", confidence=0.6,
    )
    h2 = Hypothesis(
        hunter="hunter-authn-authz", shape="sqli",  # different hunter, same shape+loc
        repo="api", file="db.py", line=44,  # within +/- 5
        description="same bug noticed by another hunter",
        confidence=0.5,
    )
    id1 = tmp_kg.add_hypothesis(h1)
    id2 = tmp_kg.add_hypothesis(h2)
    assert id1 == id2  # merged
    hyps = tmp_kg.list_hypotheses()
    assert len(hyps) == 1
    # Both hunters listed in seen_by
    assert "hunter-injection" in hyps[0]["seen_by"]
    assert "hunter-authn-authz" in hyps[0]["seen_by"]


def test_hypothesis_no_dedup_different_shape(tmp_kg):
    h1 = Hypothesis(hunter="a", shape="sqli", repo="api",
                     file="db.py", line=42, description="x", confidence=0.5)
    h2 = Hypothesis(hunter="b", shape="xss", repo="api",
                     file="db.py", line=42, description="y", confidence=0.5)
    id1 = tmp_kg.add_hypothesis(h1)
    id2 = tmp_kg.add_hypothesis(h2)
    assert id1 != id2
    assert len(tmp_kg.list_hypotheses()) == 2


def test_finding_confirms_hypothesis(tmp_kg):
    h = Hypothesis(hunter="a", shape="sqli", repo="api",
                    file="db.py", line=42, description="x", confidence=0.6)
    hid = tmp_kg.add_hypothesis(h)
    f = Finding(
        hypothesis_id=hid, title="SQL injection in /search",
        severity="critical",
        validator_summary="confirmed via DAST",
    )
    fid = tmp_kg.add_finding(f)
    hyps = tmp_kg.list_hypotheses()
    assert hyps[0]["status"] == "confirmed"
    assert hyps[0]["finding_id"] == fid


def test_primitive_chain_explored_marker(tmp_kg):
    h = Hypothesis(hunter="a", shape="ssrf", description="x", confidence=0.5)
    hid = tmp_kg.add_hypothesis(h)
    f = Finding(hypothesis_id=hid, title="x", severity="high",
                 validator_summary="x")
    fid = tmp_kg.add_finding(f)
    p = Primitive(
        finding_id=fid, name="SSRF in proxy",
        description="...", prerequisites=["net access"],
        effects=["outbound HTTP"], repos_involved=["proxy"],
    )
    pid = tmp_kg.add_primitive(p)
    assert tmp_kg.unexplored_primitive_count() == 1
    tmp_kg.mark_primitive_explored(pid)
    assert tmp_kg.unexplored_primitive_count() == 0


def test_status_summary_reflects_state(tmp_kg):
    tmp_kg.add_hypothesis(Hypothesis(
        hunter="a", shape="sqli", description="x", confidence=0.5,
    ))
    summary = tmp_kg.status_summary()
    assert summary["hypotheses_pending"] == 1
    assert summary["findings_critical"] == 0


def test_exit_criteria_all_met_check(tmp_kg):
    all_met, unmet = tmp_kg.all_exit_criteria_met()
    assert not all_met
    assert "application_model_ready" in unmet

    for name in [
        "application_model_ready", "all_hunters_returned",
        "all_hypotheses_resolved", "chain_search_exhausted",
        "reports_generated",
    ]:
        tmp_kg.set_exit_criterion(name, met=True)

    all_met, unmet = tmp_kg.all_exit_criteria_met()
    assert all_met
    assert unmet == []
