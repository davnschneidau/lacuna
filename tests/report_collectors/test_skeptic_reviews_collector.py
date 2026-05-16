"""Regression test for ``_collect_skeptic_reviews``.

Pre-fix behaviour: the collector called ``e.get("payload")`` on a row
returned by ``KG.recent_events``, where the canonical column is
``payload_json`` (a JSON-encoded string). The dict-style lookup
silently returned ``None`` for every event, so the "Skeptic Reviews"
section of every report was permanently empty.

Post-fix behaviour: drop a skeptic review into the KG via the public
``append_event`` API and assert the collector materialises it.
"""
from __future__ import annotations


def test_skeptic_reviews_are_collected_from_event_log(tmp_kg):
    from lacuna.reports.generator import _collect_skeptic_reviews

    tmp_kg.append_event(
        agent="skeptic",
        event_type="skeptic_review",
        payload={
            "finding_id": "fnd-001",
            "verdict": "challenged",
            "reasoning": "The reachability claim assumes the request hits "
                        "the unauthenticated path, but the middleware "
                        "stack always sets x-csrf before this controller.",
        },
    )
    tmp_kg.append_event(
        agent="skeptic",
        event_type="skeptic_review",
        payload={
            "finding_id": "fnd-002",
            "verdict": "confirmed",
            "reasoning": "Reproduced the exploit primitive end-to-end.",
        },
    )
    tmp_kg.append_event(
        agent="orchestrator",
        event_type="unrelated_event",
        payload={"hello": "world"},
    )

    reviews = _collect_skeptic_reviews(tmp_kg)
    by_finding = {r["finding_id"]: r for r in reviews}

    assert "fnd-001" in by_finding
    assert "fnd-002" in by_finding
    assert by_finding["fnd-001"]["verdict"] == "challenged"
    assert by_finding["fnd-001"]["notes"].startswith("The reachability claim")
    assert by_finding["fnd-002"]["verdict"] == "confirmed"


def test_skeptic_reviews_collector_is_resilient_to_malformed_payloads(tmp_kg):
    """A single corrupt event must not crash the report."""
    from lacuna.reports.generator import _collect_skeptic_reviews
    import sqlite3

    tmp_kg.append_event(
        agent="skeptic",
        event_type="skeptic_review",
        payload={
            "finding_id": "fnd-good",
            "verdict": "challenged",
            "reasoning": "valid",
        },
    )
    # Bypass the public API to inject a malformed payload_json string.
    conn: sqlite3.Connection = tmp_kg._conn  # noqa: SLF001 — intentional
    conn.execute(
        "INSERT INTO event_log (agent, event_type, payload_json) "
        "VALUES (?, ?, ?)",
        ("skeptic", "skeptic_review", "{this is not json"),
    )
    conn.commit()

    reviews = _collect_skeptic_reviews(tmp_kg)
    finding_ids = [r["finding_id"] for r in reviews]
    assert "fnd-good" in finding_ids
    # The malformed row surfaces as a {} payload — finding_id is None,
    # which is acceptable so long as the report still renders.
    assert any(r["finding_id"] is None for r in reviews)


def test_skeptic_reviews_handles_legacy_dict_payload(tmp_kg):
    """Belt-and-braces: a dict payload (legacy in-memory shape) still works."""
    from lacuna.reports.generator import _collect_skeptic_reviews

    fake_events = [
        {
            "payload": {
                "finding_id": "fnd-legacy",
                "verdict": "challenged",
                "reasoning": "legacy shape passes through",
            }
        }
    ]

    class _FakeKG:
        def recent_events(self, n, event_type):
            assert event_type == "skeptic_review"
            return fake_events

    reviews = _collect_skeptic_reviews(_FakeKG())
    assert reviews == [
        {
            "finding_id": "fnd-legacy",
            "verdict": "challenged",
            "notes": "legacy shape passes through",
        }
    ]
