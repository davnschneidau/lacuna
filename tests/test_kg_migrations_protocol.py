"""KG storage / migrations / protocol regression tests.

Covers:
- Migrations framework runs and is idempotent.
- Junction tables exist after a fresh init.
- ``KGProtocol`` is structurally satisfied by both ``KG`` and ``MockKG``.
- ``read_application_model`` caches and invalidates correctly.
- ``claim_idempotency_key`` returns True once, False thereafter.
- ``MockKG`` honours the same surface as ``KG`` for the methods the
  hooks / reporters actually call.
"""
from __future__ import annotations

import json
import sqlite3

from lacuna.kg import KG
from lacuna.kg.migrations import MIGRATIONS, applied_ids, apply_pending
from lacuna.kg.mock import MockKG
from lacuna.kg.protocol import KGProtocol


# ─── Migrations framework ──────────────────────────────────────────────────

def test_migrations_apply_in_order_on_fresh_db(tmp_path):
    db = tmp_path / "fresh.db"
    kg = KG(db)
    kg.initialize()
    conn = kg._conn  # noqa: SLF001
    done = applied_ids(conn)
    expected = {m.id for m in MIGRATIONS}
    assert done == expected
    kg.close()


def test_migrations_are_idempotent_across_open(tmp_path):
    db = tmp_path / "rerun.db"
    kg = KG(db)
    kg.initialize()
    kg.close()

    # Re-open and re-initialize. No new migrations should apply.
    kg = KG(db)
    kg.initialize()
    new = apply_pending(kg._conn)  # noqa: SLF001
    assert new == []
    kg.close()


def test_junction_tables_present_after_migration(tmp_kg):
    conn: sqlite3.Connection = tmp_kg._conn  # noqa: SLF001
    tables = {
        r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'",
        )
    }
    assert "chain_primitives" in tables
    assert "weird_composition_primitives" in tables
    assert "observation_shapes" in tables
    assert "row_quotas" in tables
    assert "idempotency_keys" in tables
    assert "schema_migrations" in tables


def test_indices_for_scan_kind_are_present(tmp_kg):
    conn: sqlite3.Connection = tmp_kg._conn  # noqa: SLF001
    indices = {
        r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'",
        )
    }
    assert "idx_hyp_kind" in indices
    assert "idx_find_kind" in indices
    assert "idx_prim_kind" in indices


# ─── read_application_model cache ──────────────────────────────────────────

def test_read_application_model_caches_after_first_call(tmp_kg):
    tmp_kg.write_application_model(
        summary_md="initial",
        facts={"application_name": "demo"},
    )
    first = tmp_kg.read_application_model()
    assert first is not None
    assert first["facts"]["application_name"] == "demo"

    cached_after_first = tmp_kg._application_model_cache  # noqa: SLF001
    assert cached_after_first is not None
    sentinel, value = cached_after_first
    assert sentinel is True
    assert value == first

    second = tmp_kg.read_application_model()
    assert second is first  # same dict reference proves cache hit


def test_read_application_model_caches_none_result(tmp_kg):
    """Pre-recon callers must not pay for repeated round-trips."""
    assert tmp_kg.read_application_model() is None
    cached = tmp_kg._application_model_cache  # noqa: SLF001
    assert cached == (True, None)


def test_read_application_model_cache_invalidates_on_write(tmp_kg):
    tmp_kg.write_application_model("v1", {"x": 1})
    assert tmp_kg.read_application_model()["facts"] == {"x": 1}

    tmp_kg.write_application_model("v2", {"x": 2})
    assert tmp_kg.read_application_model()["facts"] == {"x": 2}


# ─── Idempotency keys ──────────────────────────────────────────────────────

def test_claim_idempotency_key_is_exactly_once(tmp_kg):
    first = tmp_kg.claim_idempotency_key("hash:abc", "hypotheses", "hyp-1")
    assert first is True
    second = tmp_kg.claim_idempotency_key("hash:abc", "hypotheses", "hyp-1")
    assert second is False


def test_claim_idempotency_key_disjoint_keys_succeed(tmp_kg):
    assert tmp_kg.claim_idempotency_key("hash:a", "hypotheses", "x") is True
    assert tmp_kg.claim_idempotency_key("hash:b", "hypotheses", "y") is True


# ─── KGProtocol ─────────────────────────────────────────────────────────────

def test_kg_satisfies_protocol(tmp_kg):
    """Runtime check that the live KG fulfils the protocol surface.

    Adding a method to ``KGProtocol`` without implementing it on
    ``KG`` makes this assertion fail at test time, which is the
    "before merge" enforcement we want.
    """
    assert isinstance(tmp_kg, KGProtocol)


def test_mock_kg_satisfies_protocol():
    mock = MockKG()
    mock.initialize()
    assert isinstance(mock, KGProtocol)


def test_mock_kg_round_trip_meta_and_events():
    mock = MockKG()
    mock.initialize()
    mock.set_meta("foo", "bar")
    assert mock.get_meta("foo") == "bar"

    mock.append_event("system", "scan_started", {"a": 1})
    events = mock.recent_events(event_type="scan_started")
    assert len(events) == 1
    payload = json.loads(events[0]["payload_json"])
    assert payload == {"a": 1}


def test_mock_kg_adversary_verdict_surface():
    mock = MockKG()
    mock.initialize()
    mock.findings.append({"id": "fnd-1"})
    assert mock.findings_missing_adversary_verdict() == ["fnd-1"]
    mock.record_adversary_verdict("fnd-1", "adversary", "confirmed")
    assert mock.findings_missing_adversary_verdict() == []


def test_mock_kg_exit_criteria_round_trip():
    mock = MockKG()
    mock.initialize()
    ok, unmet = mock.all_exit_criteria_met()
    assert ok is False and len(unmet) > 0
    for crit in list(unmet):
        mock.set_exit_criterion(crit, met=True)
    ok, unmet = mock.all_exit_criteria_met()
    assert ok is True and unmet == []
