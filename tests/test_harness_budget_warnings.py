"""Harness budget warning regression tests.

``LACUNA_BUDGET_USD`` was silently parsed and later checked against a
meta-key (``token_cost_usd``) that no agent ever populated. The user
got a budget number echoed back but no actual enforcement.

The harness must now log an explicit warning that the budget is
advisory; ``_track_budget_usd`` is the helper that produces both the
parsed value and the warning text.

We test the warnings at the helper-function level so we don't have to
spin up a real ``claude`` subprocess.
"""
from __future__ import annotations


def test_track_budget_usd_warning_text(monkeypatch, capsys):
    from lacuna.harness import workspace

    monkeypatch.setenv("LACUNA_BUDGET_USD", "25.50")
    result = workspace._track_budget_usd()  # noqa: SLF001 -- test hook
    assert result == 25.50
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "LACUNA_BUDGET_USD" in combined
    assert "advisory" in combined.lower()


def test_track_budget_usd_returns_none_when_unset(monkeypatch):
    from lacuna.harness import workspace
    monkeypatch.delenv("LACUNA_BUDGET_USD", raising=False)
    assert workspace._track_budget_usd() is None  # noqa: SLF001


def test_track_budget_usd_ignores_non_numeric(monkeypatch, capsys):
    from lacuna.harness import workspace
    monkeypatch.setenv("LACUNA_BUDGET_USD", "fifty-bucks")
    assert workspace._track_budget_usd() is None  # noqa: SLF001
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "not numeric" in combined
