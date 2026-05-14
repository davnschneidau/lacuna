"""Tests for the durable event log."""
from __future__ import annotations


def test_event_append_and_recent(tmp_kg):
    eid1 = tmp_kg.append_event("orchestrator", "scan_started", {"mode": "sast"})
    eid2 = tmp_kg.append_event("recon", "tool_call", {"tool": "app_inventory"})
    eid3 = tmp_kg.append_event("recon", "tool_call", {"tool": "language_stats"})
    assert eid1 < eid2 < eid3

    recent = tmp_kg.recent_events(n=10)
    assert len(recent) == 3
    # recent_events returns reverse chronological
    assert recent[0]["id"] == eid3


def test_event_filter_by_type(tmp_kg):
    tmp_kg.append_event("orchestrator", "scan_started", {})
    tmp_kg.append_event("recon", "tool_call", {})
    tmp_kg.append_event("recon", "tool_call", {})
    tmp_kg.append_event("validator", "finding_added", {})

    tool_calls = tmp_kg.recent_events(n=10, event_type="tool_call")
    assert len(tool_calls) == 2
    assert all(e["event_type"] == "tool_call" for e in tool_calls)


def test_event_payload_roundtrip(tmp_kg):
    payload = {"complex": {"nested": [1, 2, 3], "flag": True}}
    tmp_kg.append_event("test", "complex_event", payload)
    import json
    recent = tmp_kg.recent_events(n=1, event_type="complex_event")
    assert json.loads(recent[0]["payload_json"]) == payload


def test_tool_audit_separate_from_event_log(tmp_kg):
    tmp_kg.record_tool_call(
        agent="recon", tool="app_inventory",
        args={"max_files": 5000},
        result_summary="5 repos",
    )
    # Tool audit goes to tool_audit, not event_log
    audit_rows = tmp_kg._conn.execute("SELECT * FROM tool_audit").fetchall()
    assert len(audit_rows) == 1
    assert audit_rows[0]["tool"] == "app_inventory"
    assert audit_rows[0]["args_hash"]  # hash was computed
