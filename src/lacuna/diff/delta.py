"""
Risk-timeline delta module.

Compares the current scan's findings against the previous scan stored in a
persistent KG database (LACUNA_PREV_KG_PATH). Produces:
  - new findings (introduced in this scan)
  - fixed findings (present last time, absent now)
  - persisted findings (same location, same shape, both scans)
  - regressions (fixed in a prior scan, re-introduced now)

This is the engine behind LACUNA_MODE=diff's "what changed?" report section
and the CI badge (risk going up / down / stable).

Usage:
    from lacuna.diff.delta import compute_delta, DeltaResult
    delta = compute_delta(current_kg_path, prev_kg_path)
    print(delta.summary())
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FindingSummary:
    finding_id: str
    shape: str
    severity: str
    repo: str
    file: str
    line: int | None
    title: str


@dataclass
class DeltaResult:
    new_findings: list[FindingSummary] = field(default_factory=list)
    fixed_findings: list[FindingSummary] = field(default_factory=list)
    persisted_findings: list[FindingSummary] = field(default_factory=list)
    regressions: list[FindingSummary] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Delta: +{len(self.new_findings)} new, "
            f"-{len(self.fixed_findings)} fixed, "
            f"={len(self.persisted_findings)} persisted, "
            f"!{len(self.regressions)} regressions"
        )

    def risk_direction(self) -> str:
        net = len(self.new_findings) + len(self.regressions) - len(self.fixed_findings)
        if net > 0:
            return "increasing"
        if net < 0:
            return "decreasing"
        return "stable"

    def to_dict(self) -> dict:
        return {
            "new": [_fs_to_dict(f) for f in self.new_findings],
            "fixed": [_fs_to_dict(f) for f in self.fixed_findings],
            "persisted": [_fs_to_dict(f) for f in self.persisted_findings],
            "regressions": [_fs_to_dict(f) for f in self.regressions],
            "summary": self.summary(),
            "risk_direction": self.risk_direction(),
        }


def compute_delta(
    current_kg_path: Path | str,
    prev_kg_path: Path | str | None = None,
) -> DeltaResult:
    """Compare current scan findings against a previous KG.

    If ``prev_kg_path`` is None, reads ``LACUNA_PREV_KG_PATH`` from the
    environment. Returns an empty DeltaResult if no previous KG is available.
    """
    if prev_kg_path is None:
        prev_kg_path = os.environ.get("LACUNA_PREV_KG_PATH", "")
    if not prev_kg_path or not Path(str(prev_kg_path)).exists():
        return DeltaResult()

    current = _load_findings(Path(str(current_kg_path)))
    previous = _load_findings(Path(str(prev_kg_path)))

    current_by_sig = {_fingerprint(f): f for f in current}
    previous_by_sig = {_fingerprint(f): f for f in previous}

    new: list[FindingSummary] = []
    persisted: list[FindingSummary] = []
    for sig, f in current_by_sig.items():
        if sig in previous_by_sig:
            persisted.append(f)
        else:
            new.append(f)

    fixed: list[FindingSummary] = []
    for sig, f in previous_by_sig.items():
        if sig not in current_by_sig:
            fixed.append(f)

    regressions = _check_regressions(new, Path(str(prev_kg_path)))

    result = DeltaResult(
        new_findings=new,
        fixed_findings=fixed,
        persisted_findings=persisted,
        regressions=regressions,
    )
    return result


def record_scan_run(
    kg_path: Path | str,
    mode: str,
    manifest_path: str,
    diff_base: str | None,
    diff_head: str | None,
    delta: DeltaResult | None,
) -> str:
    """Write a scan_runs row to the KG. Returns the new scan_run_id."""
    scan_id = str(uuid.uuid4())
    new_ids = json.dumps([f.finding_id for f in (delta.new_findings if delta else [])])
    fixed_ids = json.dumps([f.finding_id for f in (delta.fixed_findings if delta else [])])

    with sqlite3.connect(str(kg_path)) as conn:
        findings = conn.execute(
            "SELECT id, severity FROM findings WHERE status='confirmed'"
        ).fetchall()
        by_sev: dict[str, int] = {}
        for fid, sev in findings:
            by_sev[sev] = by_sev.get(sev, 0) + 1
        chains = conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0]

        try:
            conn.execute("""
                INSERT OR IGNORE INTO scan_runs
                  (id, started_at, mode, manifest_path, diff_base, diff_head,
                   finding_count, critical_count, high_count, medium_count, low_count,
                   chain_count, new_finding_ids, fixed_finding_ids)
                VALUES (?, datetime('now'), ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?)
            """, (
                scan_id, mode, manifest_path, diff_base, diff_head,
                len(findings),
                by_sev.get("critical", 0), by_sev.get("high", 0),
                by_sev.get("medium", 0), by_sev.get("low", 0),
                chains, new_ids, fixed_ids,
            ))
        except sqlite3.OperationalError:
            pass

        if delta:
            for f in delta.new_findings:
                _upsert_provenance(conn, f.finding_id, scan_id, "new", diff_base, diff_head)
            for f in delta.persisted_findings:
                _upsert_provenance(conn, f.finding_id, scan_id, "persisted", diff_base, diff_head)
            for f in delta.regressions:
                _upsert_provenance(conn, f.finding_id, scan_id, "regression", diff_base, diff_head)

    return scan_id


def _load_findings(kg_path: Path) -> list[FindingSummary]:
    if not kg_path.exists():
        return []
    try:
        with sqlite3.connect(str(kg_path)) as conn:
            rows = conn.execute("""
                SELECT id, shape, severity, repo, file, line, title
                FROM findings
                WHERE status = 'confirmed'
            """).fetchall()
            return [
                FindingSummary(
                    finding_id=r[0], shape=r[1], severity=r[2],
                    repo=r[3] or "", file=r[4] or "", line=r[5],
                    title=r[6] or "",
                )
                for r in rows
            ]
    except sqlite3.OperationalError:
        return []


def _fingerprint(f: FindingSummary) -> str:
    """Stable identity across scans: shape + repo + file + bucketed_line."""
    bucketed = (f.line // 10) if f.line else 0
    return f"{f.shape}\x00{f.repo}\x00{f.file}\x00{bucketed}"


def _check_regressions(
    new_findings: list[FindingSummary], prev_kg: Path
) -> list[FindingSummary]:
    """Check if any 'new' findings match fixed findings in the previous scan."""
    try:
        with sqlite3.connect(str(prev_kg)) as conn:
            fixed_rows = conn.execute("""
                SELECT fp.finding_id, f.shape, f.severity, f.repo, f.file, f.line, f.title
                FROM finding_provenance fp
                JOIN findings f ON f.id = fp.finding_id
                WHERE fp.status = 'fixed'
            """).fetchall()
    except sqlite3.OperationalError:
        return []

    fixed_sigs = {
        _fingerprint(FindingSummary(r[0], r[1], r[2], r[3] or "", r[4] or "", r[5], r[6] or ""))
        for r in fixed_rows
    }
    return [f for f in new_findings if _fingerprint(f) in fixed_sigs]


def _upsert_provenance(
    conn: sqlite3.Connection,
    finding_id: str,
    scan_id: str,
    status: str,
    diff_base: str | None,
    diff_head: str | None,
) -> None:
    try:
        conn.execute("""
            INSERT INTO finding_provenance
              (finding_id, first_scan_id, last_seen_scan_id, status, diff_base, diff_head)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
              last_seen_scan_id = excluded.last_seen_scan_id,
              status = excluded.status
        """, (finding_id, scan_id, scan_id, status, diff_base, diff_head))
    except sqlite3.OperationalError:
        pass


def _fs_to_dict(f: FindingSummary) -> dict:
    return {
        "finding_id": f.finding_id,
        "shape": f.shape,
        "severity": f.severity,
        "repo": f.repo,
        "file": f.file,
        "line": f.line,
        "title": f.title,
    }
