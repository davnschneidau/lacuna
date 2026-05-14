"""Lacuna lifecycle hooks. Each is a stdin/stdout script invoked by Claude Code."""
from __future__ import annotations

# The orchestrator/main agent has a few legitimate aliases — Claude Code
# itself sometimes self-identifies as ``main`` or ``claude``. Hooks that
# enforce "this is the top-level agent" must accept all of these.
_ORCHESTRATOR_AGENTS = frozenset({"orchestrator", "main", "claude"})


def is_orchestrator(agent: str) -> bool:
    """Return True if ``agent`` is the top-level orchestrator agent.

    Both ``stop_continuation`` (which blocks the orchestrator from
    declaring done before exit criteria are met) and
    ``subagent_stop_validate`` (which applies the global gate when the
    orchestrator itself stops) need this identity check; keep them in
    sync by routing both through this helper.
    """
    return (agent or "").strip().lower() in _ORCHESTRATOR_AGENTS
