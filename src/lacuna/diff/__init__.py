"""
Lacuna diff mode — PR-scoped scanning.

Instead of scanning the entire codebase, diff mode restricts analysis to:
  1. Files changed in the PR (git diff base..head)
  2. Files that transitively import those changed files (up to N hops)
  3. HTTP endpoints / entrypoints that call into the affected code

This cuts wall-clock time from hours to ~15 minutes for typical PRs.

Public API:
    compute_diff_scope(repo_path, base_ref, head_ref, max_depth) -> DiffScope
    DiffScope.to_env_dict()   — env vars for passing scope to child processes
    DiffScope.summary()       — human-readable summary for the kickoff prompt
"""
from __future__ import annotations

from .scope_calculator import DiffScope, compute_diff_scope
from .delta import DeltaResult, compute_delta, record_scan_run

__all__ = ["DiffScope", "compute_diff_scope", "DeltaResult", "compute_delta", "record_scan_run"]
