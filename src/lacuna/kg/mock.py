"""In-memory KG implementation for tests.

Implements :class:`KGProtocol` against Python dicts and lists. Useful
for hook / reporter unit tests that don't need transactional
guarantees or schema enforcement.

This is NOT a drop-in for production. The real KG enforces:

- ``CHECK`` constraints on verdict / status enums.
- Unique indices for dedup.
- Foreign keys for referential integrity.
- WAL journal mode for multi-process safety.

The mock honours the *Protocol* (caller's perspective) but not the
*invariants* (database's perspective). Tests that need to assert on
the invariants should still use the real :class:`KG`.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any


@dataclass
class MockKG:
    meta: dict[str, str] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    application_model: dict | None = None
    hypotheses: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    primitives: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    adversary_verdicts: list[dict] = field(default_factory=list)
    chain_adversary_verdicts: list[dict] = field(default_factory=list)
    exit_criteria: dict[str, bool] = field(default_factory=dict)
    hook_calls: list[tuple[str, str, datetime]] = field(default_factory=list)

    # ── Lifecycle ────────────────────────────────────────────────────────
    def initialize(self) -> None:
        if not self.exit_criteria:
            self.exit_criteria = {
                "application_model_ready": False,
                "all_hunters_returned": False,
                "all_hypotheses_resolved": False,
                "chain_search_exhausted": False,
                "reports_generated": False,
            }

    def close(self) -> None:
        return None

    # ── Meta ─────────────────────────────────────────────────────────────
    def get_meta(self, key: str) -> str | None:
        return self.meta.get(key)

    def set_meta(self, key: str, value: str) -> None:
        self.meta[key] = value

    # ── Events ───────────────────────────────────────────────────────────
    def append_event(
        self, agent: str, event_type: str, payload: dict[str, Any],
    ) -> int:
        import json as _j
        self.events.append({
            "id": len(self.events) + 1,
            "agent": agent,
            "event_type": event_type,
            "payload_json": _j.dumps(payload, default=str),
            "ts": datetime.now(UTC).isoformat(),
        })
        return len(self.events)

    def recent_events(
        self, n: int = 50, event_type: str | None = None,
    ) -> list[dict]:
        rows = list(reversed(self.events))
        if event_type:
            rows = [r for r in rows if r["event_type"] == event_type]
        return rows[:n]

    # ── Application model ────────────────────────────────────────────────
    def read_application_model(self) -> dict | None:
        return self.application_model

    def write_application_model(
        self, summary_md: str, facts: dict[str, Any],
    ) -> None:
        self.application_model = {"summary_md": summary_md, "facts": facts}
        self.set_exit_criterion("application_model_ready", met=True)

    # ── Hypotheses / findings / primitives / chains ──────────────────────
    def list_hypotheses(
        self, status: str | None = None,
        min_confidence: float | None = None,
    ) -> list[dict]:
        out = list(self.hypotheses)
        if status:
            out = [h for h in out if h.get("status") == status]
        if min_confidence is not None:
            out = [h for h in out if h.get("confidence", 0) >= min_confidence]
        return out

    def list_findings(self, severity: str | None = None) -> list[dict]:
        out = list(self.findings)
        if severity:
            out = [f for f in out if f.get("severity") == severity]
        return out

    def list_primitives(self) -> list:
        return list(self.primitives)

    def list_chains(self) -> list:
        return list(self.chains)

    # ── Adversary verdicts ───────────────────────────────────────────────
    def record_adversary_verdict(
        self,
        finding_id: str,
        adversary: str,
        verdict: str,
        argument_for: str | None = None,
        argument_against: str | None = None,
        reasoning: str | None = None,
        evidence: dict | None = None,
    ) -> int:
        import json as _j
        row = {
            "id": len(self.adversary_verdicts) + 1,
            "finding_id": finding_id,
            "adversary": adversary,
            "verdict": verdict,
            "argument_for": argument_for,
            "argument_against": argument_against,
            "reasoning": reasoning,
            "evidence_json": _j.dumps(evidence) if evidence else None,
            "created_at": datetime.now(UTC).isoformat(),
        }
        self.adversary_verdicts.append(row)
        return row["id"]

    def list_adversary_verdicts(
        self, finding_id: str | None = None,
    ) -> list[dict]:
        rows = list(self.adversary_verdicts)
        if finding_id:
            rows = [r for r in rows if r["finding_id"] == finding_id]
        return rows

    def findings_missing_adversary_verdict(self) -> list[str]:
        with_verdicts = {
            r["finding_id"] for r in self.adversary_verdicts
        }
        return [f["id"] for f in self.findings if f["id"] not in with_verdicts]

    # ── Exit criteria ────────────────────────────────────────────────────
    def all_exit_criteria_met(self) -> tuple[bool, list[str]]:
        unmet = [k for k, v in self.exit_criteria.items() if not v]
        return (len(unmet) == 0, unmet)

    def set_exit_criterion(
        self, name: str, met: bool, reason: str | None = None,
    ) -> None:
        self.exit_criteria[name] = bool(met)

    # ── Rate-limit ledger ────────────────────────────────────────────────
    def record_hook_tool_call(self, agent: str, tool: str) -> None:
        self.hook_calls.append((agent, tool, datetime.now(UTC)))

    def count_hook_tool_calls(
        self, agent: str, window_seconds: int,
    ) -> int:
        from datetime import timedelta
        cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
        return sum(
            1 for (a, _t, ts) in self.hook_calls
            if a == agent and ts >= cutoff
        )
