"""Mode taxonomy unit tests.

The taxonomy lives in :mod:`lacuna.kind`. These tests pin every
legacy ``LACUNA_MODE`` value to its expected
``(ScanKind, ScanScope)`` translation so future refactors that touch
``parse_legacy_mode`` can't silently shift semantics.
"""
from __future__ import annotations

import pytest

from lacuna.kind import (
    ScanKind,
    ScanScope,
    is_dast_mode,
    is_sast_only_mode,
    parse_legacy_mode,
)


@pytest.mark.parametrize(
    "raw,expected_kind,expected_scope",
    [
        ("sast", ScanKind.SAST, ScanScope.FULL),
        ("SAST", ScanKind.SAST, ScanScope.FULL),
        ("sast+dast", ScanKind.SAST_DAST, ScanScope.FULL),
        ("dast", ScanKind.SAST_DAST, ScanScope.FULL),
        ("diff", ScanKind.SAST, ScanScope.DIFF),
        ("diff-sast+dast", ScanKind.SAST_DAST, ScanScope.DIFF),
        ("", ScanKind.SAST, ScanScope.FULL),
        ("unknown_mode", ScanKind.SAST, ScanScope.FULL),
    ],
)
def test_parse_legacy_mode_round_trip(raw, expected_kind, expected_scope):
    spec = parse_legacy_mode(raw)
    assert spec.kind == expected_kind
    assert spec.scope == expected_scope


def test_is_dast_mode_covers_diff_dast():
    """The historic bug: diff mode silently kept DAST tools enabled."""
    assert is_dast_mode("sast+dast") is True
    assert is_dast_mode("diff-sast+dast") is True
    assert is_dast_mode("sast") is False
    assert is_dast_mode("diff") is False, (
        "diff mode is a SAST-shaped scope, not DAST. Failing this "
        "assertion means the gate has regressed."
    )


def test_is_sast_only_mode_is_inverse_of_is_dast_mode():
    for raw in ("sast", "sast+dast", "diff", "diff-sast+dast", "unknown"):
        assert is_sast_only_mode(raw) is not is_dast_mode(raw)


def test_legacy_mode_str_round_trip():
    """Spec → legacy string should be stable for the canonical forms."""
    cases = {
        (ScanKind.SAST, ScanScope.FULL): "sast",
        (ScanKind.SAST_DAST, ScanScope.FULL): "sast+dast",
        (ScanKind.SAST, ScanScope.DIFF): "diff",
        (ScanKind.SAST_DAST, ScanScope.DIFF): "sast+dast",
    }
    for (kind, scope), expected in cases.items():
        from lacuna.kind import ScanKindSpec
        spec = ScanKindSpec(kind=kind, scope=scope)
        assert spec.legacy_mode_str == expected
