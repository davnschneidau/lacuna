"""Scan kind / scan scope taxonomy.

Historically, ``LACUNA_MODE`` was a single string that conflated two
orthogonal axes:

- *What kind of analysis?* — static (SAST) or dynamic (DAST)?
- *What scope of code?* — whole-repo or just the diff?

The conflation led to the well-documented bug where
``LACUNA_MODE=diff`` silently kept DAST tools enabled (because the
PreToolUse hook only literal-matched the string ``"sast"``).

Phase 1 splits the concept into two enums:

- :class:`ScanKind` — ``sast`` or ``sast_dast``. Determines which MCP
  servers load, which agents are recruited, and which report template
  is emitted.
- :class:`ScanScope` — ``full`` or ``diff``. Determines which files
  are in-bounds for hunters. Diff scope is enforced by recon and the
  diff module; it has no DAST implications.

The harness builds a :class:`ScanKindSpec` from the CLI flags /
``LACUNA_MODE`` / manifest and stores it in the KG meta as
``scan_kind`` and ``scan_scope`` so every downstream consumer (hooks,
MCP servers, reporters) reads the same value.

Backward compatibility: :func:`parse_legacy_mode` accepts the legacy
strings (``"sast"``, ``"sast+dast"``, ``"diff"``) and returns the
correct ``(kind, scope)`` pair. Operators don't need to update
manifests or pipe variables to upgrade.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class ScanKind(str, Enum):
    """What kind of analysis is happening?"""

    SAST = "sast"
    SAST_DAST = "sast_dast"

    @property
    def is_dast(self) -> bool:
        return self == ScanKind.SAST_DAST


class ScanScope(str, Enum):
    """What code is in-bounds for hunters?"""

    FULL = "full"
    DIFF = "diff"

    @property
    def is_diff(self) -> bool:
        return self == ScanScope.DIFF


@dataclass(frozen=True)
class ScanKindSpec:
    """Pair of (kind, scope) that fully describes the scan shape.

    Stored to KG meta as two separate keys (``scan_kind`` and
    ``scan_scope``) so downstream queries don't have to split a single
    string. The legacy ``scan_mode`` meta is preserved for backwards
    compatibility but should be considered deprecated.
    """

    kind: ScanKind
    scope: ScanScope

    @property
    def legacy_mode_str(self) -> str:
        """Reproduce the legacy single-string mode for back-compat."""
        if self.scope == ScanScope.DIFF and self.kind == ScanKind.SAST:
            return "diff"
        if self.kind == ScanKind.SAST_DAST:
            return "sast+dast"
        return "sast"

    @property
    def supports_dast_tools(self) -> bool:
        """The PreToolUse hook and MCP wiring read this."""
        return self.kind.is_dast


# Legacy → (kind, scope) translation table.
# Anything not in here falls through to (SAST, FULL).
_LEGACY_MAP: Final[dict[str, tuple[ScanKind, ScanScope]]] = {
    "sast": (ScanKind.SAST, ScanScope.FULL),
    "sast+dast": (ScanKind.SAST_DAST, ScanScope.FULL),
    "dast": (ScanKind.SAST_DAST, ScanScope.FULL),
    "diff": (ScanKind.SAST, ScanScope.DIFF),
    "diff-sast": (ScanKind.SAST, ScanScope.DIFF),
    "diff-sast+dast": (ScanKind.SAST_DAST, ScanScope.DIFF),
}


def parse_legacy_mode(value: str) -> ScanKindSpec:
    """Translate ``LACUNA_MODE`` to a :class:`ScanKindSpec`.

    Unknown values fall through to ``(SAST, FULL)`` to keep the
    harness from refusing to start when an operator types a typo.
    The harness logs the fallback so it's not invisible.
    """
    value = (value or "").strip().lower()
    kind, scope = _LEGACY_MAP.get(value, (ScanKind.SAST, ScanScope.FULL))
    return ScanKindSpec(kind=kind, scope=scope)


def is_dast_mode(value: str) -> bool:
    """Convenience for hooks that only need the dast bit.

    Identical semantics to ``parse_legacy_mode(value).supports_dast_tools``
    but cheaper to read at call sites.
    """
    return parse_legacy_mode(value).supports_dast_tools


def is_sast_only_mode(value: str) -> bool:
    """The PreToolUse hook denies DAST tools when this returns True."""
    return not is_dast_mode(value)
