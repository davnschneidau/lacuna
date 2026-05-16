"""KG Protocol surface.

Historically every consumer of the knowledge graph imported
:class:`lacuna.kg.KG` directly. Tests had to either stand up a real
SQLite database (slow, requires an on-disk path, leaks state) or
monkey-patch attributes (brittle, breaks on every method addition).

This module defines :class:`KGProtocol` -- a structural Protocol that
captures the surface every consumer actually uses. It does not
attempt to enumerate the entire KG (the live class has 60+ methods);
it documents the minimal contract a hook, reporter, or MCP server
relies on. New methods should land on the Protocol *and* the
:class:`KG` implementation in the same PR.

Consumers that take a ``KGProtocol`` parameter accept either the real
:class:`KG` or :class:`lacuna.kg.mock.MockKG`. Tests build a MockKG;
production builds a real KG.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class KGProtocol(Protocol):
    """Methods every consumer of the knowledge graph is allowed to call.

    Extend cautiously: each method here is a documented public
    contract that mock implementations must honour.
    """

    # ── Lifecycle ────────────────────────────────────────────────────────
    def initialize(self) -> None: ...
    def close(self) -> None: ...

    # ── Meta ─────────────────────────────────────────────────────────────
    def get_meta(self, key: str) -> str | None: ...
    def set_meta(self, key: str, value: str) -> None: ...

    # ── Events ───────────────────────────────────────────────────────────
    def append_event(
        self, agent: str, event_type: str, payload: dict[str, Any],
    ) -> int: ...
    def recent_events(
        self, n: int = 50, event_type: str | None = None,
    ) -> list[dict]: ...

    # ── Application model ────────────────────────────────────────────────
    def read_application_model(self) -> dict | None: ...
    def write_application_model(
        self, summary_md: str, facts: dict[str, Any],
    ) -> None: ...

    # ── Hypotheses / findings / primitives / chains ──────────────────────
    def list_hypotheses(
        self, status: str | None = None,
        min_confidence: float | None = None,
    ) -> list[dict]: ...
    def list_findings(self, severity: str | None = None) -> list[dict]: ...
    def list_primitives(self) -> list: ...
    def list_chains(self) -> list: ...

    # ── Adversary verdicts (Phase 2) ─────────────────────────────────────
    def record_adversary_verdict(
        self,
        finding_id: str,
        adversary: str,
        verdict: str,
        argument_for: str | None = None,
        argument_against: str | None = None,
        reasoning: str | None = None,
        evidence: dict | None = None,
    ) -> int: ...
    def list_adversary_verdicts(
        self, finding_id: str | None = None,
    ) -> list[dict]: ...
    def findings_missing_adversary_verdict(self) -> list[str]: ...

    # ── Exit criteria ────────────────────────────────────────────────────
    def all_exit_criteria_met(self) -> tuple[bool, list[str]]: ...
    def set_exit_criterion(
        self, name: str, met: bool, reason: str | None = None,
    ) -> None: ...

    # ── Rate-limit ledger ────────────────────────────────────────────────
    def record_hook_tool_call(self, agent: str, tool: str) -> None: ...
    def count_hook_tool_calls(
        self, agent: str, window_seconds: int,
    ) -> int: ...
