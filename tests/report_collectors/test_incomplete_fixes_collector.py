"""Regression test for ``_collect_incomplete_fixes``.

Pre-fix behaviour: the collector filtered by ``h.get("source_hunter")``,
a column that does not exist in the live ``hypotheses`` schema, and
referenced ``parent_finding_id`` / ``cwe`` columns that also don't
exist. As a result the "Incomplete Fixes" report section was always
empty even when patch-archaeologist had flagged real cases.

Post-fix behaviour: filter by the real ``hunter`` column and join
per-hypothesis metadata from ``event_log`` events of type
``incomplete_fix_metadata`` that the agent is expected to emit
alongside the draft.
"""
from __future__ import annotations

from lacuna.kg import Hypothesis


def _make_hyp(
    hid: str, hunter: str, file: str = "x.py", line: int = 10,
) -> Hypothesis:
    return Hypothesis(
        id=hid,
        hunter=hunter,
        shape="memory_corruption",
        repo="example",
        file=file,
        line=line,
        description=f"draft from {hunter}",
        attacker_scenario=None,
        confidence=0.5,
        status="pending",
    )


def test_only_patch_archaeologist_hypotheses_are_surfaced(tmp_kg):
    from lacuna.reports.generator import _collect_incomplete_fixes

    tmp_kg.add_hypothesis(_make_hyp("hyp-arch-1", "patch-archaeologist"))
    tmp_kg.add_hypothesis(_make_hyp("hyp-injection", "hunter-injection"))
    all_hyps = tmp_kg.list_hypotheses()

    fixes = _collect_incomplete_fixes(tmp_kg, all_hyps)
    hyp_ids = {f["hyp_id"] for f in fixes}
    assert hyp_ids == {"hyp-arch-1"}


def test_incomplete_fix_metadata_is_joined_by_hyp_id(tmp_kg):
    """Metadata events let the report show CWE + parent-commit."""
    from lacuna.reports.generator import _collect_incomplete_fixes

    tmp_kg.add_hypothesis(_make_hyp("hyp-arch-1", "patch-archaeologist"))
    tmp_kg.append_event(
        agent="patch-archaeologist",
        event_type="incomplete_fix_metadata",
        payload={
            "hyp_id": "hyp-arch-1",
            "cwe": "CWE-416",
            "parent_commit": "deadbeefcafe",
        },
    )
    all_hyps = tmp_kg.list_hypotheses()

    fixes = _collect_incomplete_fixes(tmp_kg, all_hyps)
    assert len(fixes) == 1
    row = fixes[0]
    assert row["hyp_id"] == "hyp-arch-1"
    assert row["bug_class"] == "CWE-416"
    assert row["parent_commit_short"] == "deadbeefca"  # 10-char trim
    assert row["location"].startswith("x.py:")


def test_missing_metadata_still_surfaces_with_question_placeholders(tmp_kg):
    """Older scans without metadata events must still surface the hypothesis.

    The placeholder ``"?"`` signals "we know there's an incomplete
    fix here, we just don't have the associated CWE / commit". That's
    more useful than swallowing the row entirely.
    """
    from lacuna.reports.generator import _collect_incomplete_fixes

    tmp_kg.add_hypothesis(_make_hyp("hyp-arch-2", "patch-archaeologist"))
    all_hyps = tmp_kg.list_hypotheses()

    fixes = _collect_incomplete_fixes(tmp_kg, all_hyps)
    assert len(fixes) == 1
    assert fixes[0]["bug_class"] == "?"
    assert fixes[0]["parent_commit_short"] == "?"


def test_empty_hypothesis_list_returns_empty(tmp_kg):
    from lacuna.reports.generator import _collect_incomplete_fixes

    assert _collect_incomplete_fixes(tmp_kg, []) == []
