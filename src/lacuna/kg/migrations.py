"""KG migrations framework.

Historically, the KG schema was applied as a single ``schema.sql``
``executescript`` followed by ad-hoc additive ``ALTER TABLE`` statements
buried inside ``_apply_additive_migrations``. That worked, but had no
version pinning and no rollback story.

This module formalises the protocol:

- A ``schema_migrations`` table records every migration that has been
  applied (id, name, applied_at, sha256 of the SQL body).
- Migrations live in :data:`MIGRATIONS` as ``(id, name, up_sql)``
  tuples. The id is monotonically increasing; gaps are forbidden.
- :func:`apply_pending` runs every migration whose id is greater than
  the highest already-applied id, in order, inside a single
  transaction per migration. If a migration fails, the transaction is
  rolled back and the function raises -- the next call to
  ``apply_pending`` will retry from the same point.

The historic ``_apply_additive_migrations`` shim is preserved as
migration ``001`` so existing scans don't need any special handling.
Each subsequent migration adds one focused change.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class Migration:
    id: int
    name: str
    up_sql: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.up_sql.encode("utf-8")).hexdigest()


# ── Migration definitions ───────────────────────────────────────────────────

_M001_KIND_COLUMNS = """
-- scan_kind on every core table so reports can partition findings by
-- SAST vs DAST origin.
ALTER TABLE hypotheses ADD COLUMN scan_kind TEXT;
ALTER TABLE findings   ADD COLUMN scan_kind TEXT;
ALTER TABLE primitives ADD COLUMN scan_kind TEXT;
ALTER TABLE chains     ADD COLUMN scan_kind TEXT;
"""

_M002_ADVERSARY_TABLES = """
-- Adversary verdicts as first-class rows.
CREATE TABLE IF NOT EXISTS adversary_verdicts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL REFERENCES findings(id),
    adversary     TEXT NOT NULL,
    verdict       TEXT NOT NULL CHECK (verdict IN (
                      'refute_pending', 'confirmed', 'downgrade',
                      'refuted', 'needs_human'
                  )),
    argument_for  TEXT,
    argument_against TEXT,
    reasoning     TEXT,
    evidence_json TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_adv_finding
    ON adversary_verdicts(finding_id, adversary);

CREATE TABLE IF NOT EXISTS chain_adversary_verdicts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id      TEXT NOT NULL,
    adversary     TEXT NOT NULL,
    verdict       TEXT NOT NULL CHECK (verdict IN (
                      'refute_pending', 'confirmed', 'downgrade',
                      'refuted', 'needs_human'
                  )),
    reasoning     TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_chain_adv_chain
    ON chain_adversary_verdicts(chain_id, adversary);
"""

_M003_JUNCTION_TABLES = """
-- Junction tables replace comma-separated ID lists. Old code paths can
-- still read the JSON columns; new writers should populate the
-- junctions in addition.
CREATE TABLE IF NOT EXISTS chain_primitives (
    chain_id      TEXT NOT NULL,
    primitive_id  TEXT NOT NULL,
    position      INTEGER NOT NULL,
    PRIMARY KEY (chain_id, primitive_id),
    FOREIGN KEY (chain_id) REFERENCES chains(id),
    FOREIGN KEY (primitive_id) REFERENCES primitives(id)
);
CREATE INDEX IF NOT EXISTS idx_chain_prim_chain ON chain_primitives(chain_id);
CREATE INDEX IF NOT EXISTS idx_chain_prim_primitive ON chain_primitives(primitive_id);

CREATE TABLE IF NOT EXISTS weird_composition_primitives (
    composition_id INTEGER NOT NULL,
    primitive_id   TEXT NOT NULL,
    PRIMARY KEY (composition_id, primitive_id)
);

CREATE TABLE IF NOT EXISTS observation_shapes (
    observation_id INTEGER NOT NULL,
    shape          TEXT NOT NULL,
    PRIMARY KEY (observation_id, shape)
);
CREATE INDEX IF NOT EXISTS idx_obs_shape ON observation_shapes(shape);
"""

_M004_INDICES_AND_QUOTAS = """
-- Indices for the hot paths and a row quota table that the harness
-- checks at scan end.
CREATE INDEX IF NOT EXISTS idx_hyp_kind  ON hypotheses(scan_kind);
CREATE INDEX IF NOT EXISTS idx_find_kind ON findings(scan_kind);
CREATE INDEX IF NOT EXISTS idx_prim_kind ON primitives(scan_kind);

CREATE TABLE IF NOT EXISTS row_quotas (
    table_name TEXT PRIMARY KEY,
    max_rows   INTEGER NOT NULL
);

-- Sensible defaults; the harness can override per-scan via UPDATE.
INSERT OR IGNORE INTO row_quotas (table_name, max_rows) VALUES
    ('hypotheses', 50000),
    ('findings',   10000),
    ('primitives', 10000),
    ('chains',     5000),
    ('event_log',  500000);

-- Idempotency keys for at-least-once writers. Hunters writing the same
-- hypothesis twice should be a no-op even if dedup keys
-- (shape, repo, file, line/5) shift.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key       TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    row_id    TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


MIGRATIONS: list[Migration] = [
    Migration(1, "scan_kind_columns", _M001_KIND_COLUMNS),
    Migration(2, "adversary_tables", _M002_ADVERSARY_TABLES),
    Migration(3, "junction_tables", _M003_JUNCTION_TABLES),
    Migration(4, "indices_and_quotas", _M004_INDICES_AND_QUOTAS),
]


# ── Runner ──────────────────────────────────────────────────────────────────

_SCHEMA_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA_TABLE)
    conn.commit()


def applied_ids(conn: sqlite3.Connection) -> set[int]:
    _ensure_table(conn)
    rows = conn.execute("SELECT id FROM schema_migrations").fetchall()
    return {int(r[0]) for r in rows}


def apply_pending(conn: sqlite3.Connection) -> list[Migration]:
    """Apply every migration whose id has not yet been recorded.

    Returns the list of migrations that were applied this call.
    Idempotent. Migrations that fail are rolled back; the function
    raises so the operator sees the failure immediately rather than
    silently continuing with a half-migrated DB.

    Note on legacy DBs: many of these migrations use
    ``CREATE TABLE IF NOT EXISTS`` so applying ``001`` for the first
    time on a DB that already saw the historic
    ``_apply_additive_migrations`` won't break -- the ``ALTER TABLE``
    inside ``001`` is wrapped in a per-statement try/except that
    swallows ``duplicate column name``. This is the migration that
    bridges the historic shim to the new framework.
    """
    _ensure_table(conn)
    done = applied_ids(conn)
    applied_now: list[Migration] = []
    for m in sorted(MIGRATIONS, key=lambda x: x.id):
        if m.id in done:
            continue
        try:
            _apply_one(conn, m)
        except Exception:
            conn.rollback()
            raise
        applied_now.append(m)
    return applied_now


def _apply_one(conn: sqlite3.Connection, m: Migration) -> None:
    """Apply a single migration.

    ``executescript`` auto-commits on each statement boundary in
    SQLite, so we hand-parse on ``;`` and execute statements
    individually. Statements that fail with ``duplicate column name``
    (legacy ALTER TABLE replays) are swallowed so the migration is
    idempotent across upgrade paths.

    Transaction handling: we rely on sqlite3's implicit transaction
    behaviour rather than ``BEGIN`` / ``COMMIT``, because callers
    like :class:`KG` may already be inside a transaction set up by
    ``executescript``. The final ``commit()`` flushes everything.
    """
    statements = _split_sql(m.up_sql)
    for stmt in statements:
        if not stmt:
            continue
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "duplicate column name" in msg:
                continue
            raise RuntimeError(
                f"migration {m.id} ({m.name}) failed at statement: "
                f"{stmt[:200]!r}: {e}"
            ) from e
    conn.execute(
        "INSERT INTO schema_migrations (id, name, sha256) VALUES (?, ?, ?)",
        (m.id, m.name, m.sha256),
    )
    conn.commit()


def _split_sql(body: str) -> list[str]:
    """Split a SQL script on ``;`` outside comments and strings.

    Simple state machine — enough for the migration bodies we ship.
    Tracks single-quoted strings and SQL line comments (``--``); any
    semicolon outside both is a statement terminator. Whitespace-only
    fragments are dropped.
    """
    out: list[str] = []
    buf: list[str] = []
    in_str = False
    in_comment = False
    i = 0
    while i < len(body):
        ch = body[i]
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if in_comment:
            if ch == "\n":
                in_comment = False
            i += 1
            continue
        if in_str:
            buf.append(ch)
            if ch == "'" and nxt == "'":
                buf.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_str = False
            i += 1
            continue
        if ch == "-" and nxt == "-":
            in_comment = True
            i += 2
            continue
        if ch == "'":
            buf.append(ch)
            in_str = True
            i += 1
            continue
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out
