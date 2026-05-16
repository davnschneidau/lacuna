"""
Knowledge graph client for Lacuna.

The KG is the durable memory of a scan. Agents come and go, transcripts get
compacted, but the KG is the source of truth. Everything important is here.

Ephemeral mode: a fresh KG is created at the start of each scan. There is no
cross-scan memory. To compare scans, archive the report artifacts.

Concurrency model
=================

The KG is safe under cross-process concurrent writes (subagent spawns) via
SQLite WAL + retry. ``add_hypothesis`` performs *atomic* dedup: SELECT and
INSERT/UPDATE run in a single ``BEGIN IMMEDIATE`` transaction so two
hunters racing to publish the same hypothesis can't both win. Multi-step
writes that must be all-or-nothing (``add_finding`` + the implied
``update_hypothesis_status``; ``record_fuzz_run`` + an immediate
``record_fuzz_crash``) share one transaction.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any


def _rand_id() -> str:
    """Short, non-cryptographic random ID for human-readable references.

    Note: this is *not* a ULID. Earlier revisions misnamed the function
    ``_ulid`` despite returning a uuid4-derived hex slice with no
    timestamp prefix. The kept-for-compat alias below preserves the old
    name for any external callers that imported it.
    """
    return uuid.uuid4().hex[:12]


# Back-compat alias. New code should call ``_rand_id``.
_ulid = _rand_id


def hyp_id() -> str:
    return f"hyp-{_rand_id()}"


def find_id() -> str:
    return f"fnd-{_rand_id()}"


def prim_id() -> str:
    return f"prim-{_rand_id()}"


def chain_id() -> str:
    return f"chain-{_rand_id()}"


@dataclass
class Hypothesis:
    id: str = field(default_factory=hyp_id)
    hunter: str = ""
    shape: str = ""
    repo: str | None = None
    file: str | None = None
    line: int | None = None
    description: str = ""
    attacker_scenario: str | None = None
    confidence: float = 0.3
    status: str = "pending"  # pending|validating|confirmed|refuted|needs_human
    refutation_reason: str | None = None
    finding_id: str | None = None


@dataclass
class Finding:
    id: str = field(default_factory=find_id)
    hypothesis_id: str = ""
    title: str = ""
    severity: str = "medium"  # low|medium|high|critical
    cvss_vector: str | None = None
    cwes: list[str] | None = None
    repos_involved: list[str] = field(default_factory=list)
    validator_summary: str = ""
    remediation_md: str | None = None


@dataclass
class Primitive:
    id: str = field(default_factory=prim_id)
    finding_id: str = ""
    name: str = ""
    description: str = ""
    prerequisites: list[str] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)
    repos_involved: list[str] = field(default_factory=list)


@dataclass
class Chain:
    id: str = field(default_factory=chain_id)
    primitive_ids: list[str] = field(default_factory=list)
    goal: str = "rce"
    combined_severity: str = "high"
    narrative_md: str = ""


def obs_id() -> str:
    return f"obs-{_rand_id()}"


def cap_id() -> str:
    return f"cap-{_rand_id()}"


def weird_id() -> str:
    return f"weird-{_rand_id()}"


def flow_id() -> str:
    return f"flow-{_rand_id()}"


@dataclass
class Observation:
    id: str = field(default_factory=obs_id)
    author_agent: str = ""
    kind: str = ""
    repo: str | None = None
    file: str | None = None
    line: int | None = None
    summary: str = ""
    detail_md: str | None = None
    affects_shapes: list[str] = field(default_factory=list)


@dataclass
class Gadget:
    id: str = ""
    language: str = ""
    library: str = ""
    version_range: str = ""
    gadget_name: str = ""
    impact: str = ""
    notes_md: str = ""
    poc_template: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class Capability:
    id: str = field(default_factory=cap_id)
    asset_kind: str = ""
    asset_name: str = ""
    holder_repo: str = ""
    grants: list[str] = field(default_factory=list)


@dataclass
class WeirdComposition:
    id: str = field(default_factory=weird_id)
    primitive_ids: list[str] = field(default_factory=list)
    intended_use: str = ""
    unintended_use: str = ""
    enables_goal: str = ""
    confidence: float = 0.5


@dataclass
class FlowPath:
    id: str = field(default_factory=flow_id)
    repo: str = ""
    source_kind: str = ""
    sink_kind: str = ""
    path: list[dict] = field(default_factory=list)
    sanitizers_crossed: list[str] = field(default_factory=list)
    confidence: float = 0.5


class KG:
    """SQLite-backed knowledge graph.

    Single-process safe; cross-process safe via SQLite's WAL + retry. Subagent
    spawns may concurrently write — the design assumes the dedup pass at write
    time handles near-duplicate hypotheses.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.execute("PRAGMA journal_mode = WAL;")

    # ── lifecycle ───────────────────────────────────────────────────────────

    def initialize(self) -> None:
        """Run schema. Called once at scan start.

        The formal migrations framework in :mod:`lacuna.kg.migrations`
        is the canonical source of schema changes. The legacy
        ``_apply_additive_migrations`` shim is kept here for DBs that
        pre-date the ``schema_migrations`` table; calling it after
        ``apply_pending`` is harmless because every statement is
        idempotent.
        """
        schema = (resources.files("lacuna.kg") / "schema.sql").read_text()
        self._conn.executescript(schema)
        self._conn.commit()
        from .migrations import apply_pending
        apply_pending(self._conn)
        # Legacy compat shim — runs after the migrations framework so
        # DBs that pre-date this module still pick up the additive
        # columns. The migrations themselves are idempotent.
        self._apply_additive_migrations()

    def _apply_additive_migrations(self) -> None:
        """Run idempotent additive ALTER TABLE statements.

        Each statement is wrapped in a try/except — SQLite raises
        ``OperationalError: duplicate column name`` when the column
        already exists, which we silently swallow so the call is
        idempotent across scan restarts.
        """
        additive = [
            ("hypotheses", "scan_kind", "TEXT"),
            ("findings", "scan_kind", "TEXT"),
            ("primitives", "scan_kind", "TEXT"),
            ("chains", "scan_kind", "TEXT"),
        ]
        for table, col, decl in additive:
            try:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {decl}"
                )
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if "duplicate column name" in msg or "no such table" in msg:
                    continue
                raise

        # Adversary verdicts. The original skeptic emitted
        # ``event_log`` rows of type ``skeptic_review`` -- durable, but
        # not enumerable. The verdicts table makes "every finding has
        # an adversary verdict before scan exit" an expressible
        # invariant (the Stop hook joins ``findings`` to
        # ``adversary_verdicts`` and refuses to finish if any are
        # missing).
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS adversary_verdicts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id    TEXT NOT NULL REFERENCES findings(id),
                adversary     TEXT NOT NULL,
                verdict       TEXT NOT NULL CHECK (verdict IN (
                                  'refute_pending',
                                  'confirmed',
                                  'downgrade',
                                  'refuted',
                                  'needs_human'
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
                                  'refute_pending',
                                  'confirmed',
                                  'downgrade',
                                  'refuted',
                                  'needs_human'
                              )),
                reasoning     TEXT,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_chain_adv_chain
                ON chain_adversary_verdicts(chain_id, adversary);
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ── event log ───────────────────────────────────────────────────────────

    def append_event(
        self,
        agent: str,
        event_type: str,
        payload: dict[str, Any],
        parent_event_id: int | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO event_log (agent, event_type, payload_json, parent_event_id) "
            "VALUES (?, ?, ?, ?)",
            (agent, event_type, json.dumps(payload, default=str), parent_event_id),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return int(cur.lastrowid)

    def recent_events(self, n: int = 50, event_type: str | None = None) -> list[dict]:
        if event_type:
            rows = self._conn.execute(
                "SELECT * FROM event_log WHERE event_type = ? "
                "ORDER BY id DESC LIMIT ?",
                (event_type, n),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── application model ───────────────────────────────────────────────────

    def write_application_model(self, summary_md: str, facts: dict[str, Any]) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM application_model")
            c.execute(
                "INSERT INTO application_model (summary_md, facts_json) VALUES (?, ?)",
                (summary_md, json.dumps(facts)),
            )
        self.set_exit_criterion("application_model_ready", met=True)
        # Invalidate the read cache (see read_application_model).
        self._application_model_cache = None

    def read_application_model(self) -> dict | None:
        """Return the application model with a per-instance cache.

        Every report build calls this method 4-5 times (exec context,
        tech context, repos count, chain context, app_name fallback)
        and each call was hitting the DB plus JSON-decoding the facts
        column. The cache makes repeated reads free; writes invalidate
        it via :meth:`write_application_model`. The cache key is
        ``True`` so ``None`` results are also cached (otherwise
        pre-recon callers would keep paying for the round-trip).
        """
        cached = getattr(self, "_application_model_cache", None)
        if cached is not None:
            sentinel, value = cached
            if sentinel:
                return value
        row = self._conn.execute(
            "SELECT * FROM application_model LIMIT 1",
        ).fetchone()
        if not row:
            self._application_model_cache = (True, None)
            return None
        out = {
            "summary_md": row["summary_md"],
            "facts": json.loads(row["facts_json"]),
        }
        self._application_model_cache = (True, out)
        return out

    def claim_idempotency_key(
        self, key: str, table_name: str, row_id: str,
    ) -> bool:
        """Claim an idempotency key for a writer.

        Returns True if the key was newly inserted (caller should
        proceed with the write), False if it was already present
        (caller should skip). Two callers:

        - Hunters calling ``add_hypothesis`` with an explicit external
          dedup key that's stronger than the (shape, repo, file,
          line/5) dedup index (e.g. a payload hash).
        - The harness re-claiming a known-seeded row after a
          ``--resume`` restart.
        """
        try:
            self._conn.execute(
                "INSERT INTO idempotency_keys (key, table_name, row_id) "
                "VALUES (?, ?, ?)",
                (key, table_name, row_id),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    # ── hypotheses ──────────────────────────────────────────────────────────

    def add_hypothesis(self, h: Hypothesis) -> str:
        """Insert or merge a hypothesis.

        Dedup rule: same ``shape`` + ``repo`` + ``file`` within +/- 5 lines is
        considered the same hypothesis. We rely on:

        1. **The partial unique index** in ``schema.sql`` on
           ``(shape, repo, file, line / 5)`` to make duplicate inserts
           impossible at the DB layer.
        2. **An INTEGRITY-ERROR retry** so two hunters who race to publish
           the same hypothesis both end up merging into the same winner row.

        Both steps run inside a single SQLite transaction so a crash mid-way
        leaves the table consistent.
        """
        existing_id: str | None = None
        with self.tx() as c:
            if h.repo and h.file:
                existing = c.execute(
                    "SELECT id, seen_by FROM hypotheses "
                    "WHERE shape = ? AND repo = ? AND file = ? "
                    "AND ABS(COALESCE(line, 0) - COALESCE(?, 0)) <= 5",
                    (h.shape, h.repo, h.file, h.line),
                ).fetchone()
                if existing:
                    seen_by = (
                        (existing["seen_by"] or "").split(",")
                        if existing["seen_by"] else []
                    )
                    if h.hunter and h.hunter not in seen_by:
                        seen_by.append(h.hunter)
                    c.execute(
                        "UPDATE hypotheses SET seen_by = ?, "
                        "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (",".join(seen_by), existing["id"]),
                    )
                    existing_id = existing["id"]
            if existing_id is None:
                try:
                    c.execute(
                        """INSERT INTO hypotheses
                           (id, hunter, shape, repo, file, line, description,
                            attacker_scenario, confidence, status, seen_by)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            h.id, h.hunter, h.shape, h.repo, h.file, h.line,
                            h.description, h.attacker_scenario, h.confidence,
                            h.status, h.hunter,
                        ),
                    )
                except sqlite3.IntegrityError:
                    # Partial unique index caught a race with a peer writer.
                    # Re-do the lookup and merge into the winner.
                    winner = c.execute(
                        "SELECT id, seen_by FROM hypotheses "
                        "WHERE shape = ? AND repo = ? AND file = ? "
                        "AND ABS(COALESCE(line, 0) - COALESCE(?, 0)) <= 5",
                        (h.shape, h.repo, h.file, h.line),
                    ).fetchone()
                    if winner:
                        seen_by = (
                            (winner["seen_by"] or "").split(",")
                            if winner["seen_by"] else []
                        )
                        if h.hunter and h.hunter not in seen_by:
                            seen_by.append(h.hunter)
                        c.execute(
                            "UPDATE hypotheses SET seen_by = ?, "
                            "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                            (",".join(seen_by), winner["id"]),
                        )
                        existing_id = winner["id"]
                    else:
                        raise
        if existing_id is not None:
            return existing_id
        self.append_event(h.hunter, "hypothesis_added", asdict(h))
        return h.id

    def list_hypotheses(
        self, status: str | None = None, min_confidence: float | None = None
    ) -> list[dict]:
        q = "SELECT * FROM hypotheses WHERE 1=1"
        args: list[Any] = []
        if status:
            q += " AND status = ?"
            args.append(status)
        if min_confidence is not None:
            q += " AND confidence >= ?"
            args.append(min_confidence)
        q += " ORDER BY confidence DESC, created_at"
        return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    def get_hypothesis(self, hyp_id: str) -> dict | None:
        """Direct fetch by ID. Use this instead of ``list_hypotheses()`` +
        filter when you only need one hypothesis."""
        r = self._conn.execute(
            "SELECT * FROM hypotheses WHERE id = ?", (hyp_id,),
        ).fetchone()
        return dict(r) if r else None

    def update_hypothesis_status(
        self, hid: str, status: str, refutation_reason: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE hypotheses SET status = ?, refutation_reason = ?, "
                "finding_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, refutation_reason, finding_id, hid),
            )

    # ── findings & evidence ─────────────────────────────────────────────────

    def add_finding(self, f: Finding) -> str:
        """Insert a finding and confirm its parent hypothesis atomically.

        Both writes run inside one transaction. If either fails the other is
        rolled back so we never have a hypothesis pointing at a finding-id
        that doesn't exist (or vice-versa).
        """
        cwes_json = json.dumps(f.cwes) if f.cwes else None
        repos_json = json.dumps(list(f.repos_involved or []))
        with self.tx() as c:
            c.execute(
                """INSERT INTO findings
                   (id, hypothesis_id, title, severity, cvss_vector, cwes,
                    repos_involved_json, validator_summary, remediation_md)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    f.id, f.hypothesis_id, f.title, f.severity, f.cvss_vector,
                    cwes_json, repos_json, f.validator_summary, f.remediation_md,
                ),
            )
            if f.hypothesis_id:
                c.execute(
                    "UPDATE hypotheses SET status = 'confirmed', "
                    "finding_id = ?, updated_at = CURRENT_TIMESTAMP "
                    "WHERE id = ?",
                    (f.id, f.hypothesis_id),
                )
        self.append_event("validator", "finding_added", asdict(f))
        return f.id

    def list_findings(self, severity: str | None = None) -> list[dict]:
        if severity:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE severity = ? "
                "ORDER BY validated_at DESC", (severity,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY "
                "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
                "WHEN 'medium' THEN 3 ELSE 4 END, validated_at DESC"
            ).fetchall()
        return [self._inflate_finding(dict(r)) for r in rows]

    def get_finding(self, finding_id: str) -> dict | None:
        """Direct fetch by ID."""
        r = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,),
        ).fetchone()
        return self._inflate_finding(dict(r)) if r else None

    @staticmethod
    def _inflate_finding(row: dict) -> dict:
        """Decode JSON-stored columns back to Python objects for callers."""
        if "cwes" in row and isinstance(row["cwes"], str):
            try:
                row["cwes"] = json.loads(row["cwes"]) if row["cwes"] else []
            except (TypeError, json.JSONDecodeError):
                # Legacy comma-string fallback
                row["cwes"] = [
                    s for s in (row["cwes"] or "").split(",") if s
                ]
        if "repos_involved_json" in row:
            try:
                row["repos_involved"] = (
                    json.loads(row["repos_involved_json"])
                    if row["repos_involved_json"] else []
                )
            except (TypeError, json.JSONDecodeError):
                row["repos_involved"] = []
        return row

    def attach_evidence(self, finding_id: str, kind: str, payload_path: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO evidence (finding_id, kind, payload_path) VALUES (?, ?, ?)",
                (finding_id, kind, payload_path),
            )

    def get_evidence(self, finding_id: str) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ?", (finding_id,)
            ).fetchall()
        ]

    # ── primitives ──────────────────────────────────────────────────────────

    def add_primitive(self, p: Primitive) -> str:
        with self.tx() as c:
            c.execute(
                """INSERT INTO primitives
                   (id, finding_id, name, description,
                    prerequisites_json, effects_json, repos_involved_json)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    p.id, p.finding_id, p.name, p.description,
                    json.dumps(p.prerequisites), json.dumps(p.effects),
                    json.dumps(list(p.repos_involved or [])),
                ),
            )
        self.append_event("validator", "primitive_added", asdict(p))
        return p.id

    def list_primitives(self) -> list[Primitive]:
        out: list[Primitive] = []
        for r in self._conn.execute("SELECT * FROM primitives ORDER BY created_at"):
            try:
                repos = json.loads(r["repos_involved_json"] or "[]")
            except (TypeError, json.JSONDecodeError):
                repos = []
            out.append(Primitive(
                id=r["id"], finding_id=r["finding_id"] or "", name=r["name"],
                description=r["description"],
                prerequisites=json.loads(r["prerequisites_json"]),
                effects=json.loads(r["effects_json"]),
                repos_involved=repos,
            ))
        return out

    def mark_primitive_explored(self, pid: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE primitives SET chain_explored = 1 WHERE id = ?", (pid,))

    def get_primitive(self, pid: str) -> Primitive | None:
        r = self._conn.execute(
            "SELECT * FROM primitives WHERE id = ?", (pid,),
        ).fetchone()
        if not r:
            return None
        try:
            repos = json.loads(r["repos_involved_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            repos = []
        return Primitive(
            id=r["id"], finding_id=r["finding_id"] or "", name=r["name"],
            description=r["description"],
            prerequisites=json.loads(r["prerequisites_json"]),
            effects=json.loads(r["effects_json"]),
            repos_involved=repos,
        )

    def unexplored_primitive_count(self) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) FROM primitives WHERE chain_explored = 0"
        ).fetchone()[0])

    # ── chains ──────────────────────────────────────────────────────────────

    def add_chain(self, c: Chain) -> str:
        with self.tx() as conn:
            conn.execute(
                """INSERT INTO chains
                   (id, primitive_ids_json, goal, combined_severity, narrative_md)
                   VALUES (?,?,?,?,?)""",
                (
                    c.id, json.dumps(c.primitive_ids), c.goal,
                    c.combined_severity, c.narrative_md,
                ),
            )
        self.append_event("chain-builder", "chain_added", asdict(c))
        return c.id

    def list_chains(self) -> list[Chain]:
        out: list[Chain] = []
        for r in self._conn.execute("SELECT * FROM chains ORDER BY created_at"):
            out.append(Chain(
                id=r["id"], primitive_ids=json.loads(r["primitive_ids_json"]),
                goal=r["goal"], combined_severity=r["combined_severity"],
                narrative_md=r["narrative_md"],
            ))
        return out

    def get_chain(self, cid: str) -> Chain | None:
        r = self._conn.execute(
            "SELECT * FROM chains WHERE id = ?", (cid,),
        ).fetchone()
        if not r:
            return None
        return Chain(
            id=r["id"], primitive_ids=json.loads(r["primitive_ids_json"]),
            goal=r["goal"], combined_severity=r["combined_severity"],
            narrative_md=r["narrative_md"],
        )

    # ── exit criteria ───────────────────────────────────────────────────────

    def set_exit_criterion(self, name: str, met: bool, reason: str | None = None) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO exit_criteria (name, met, reason) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET met=excluded.met, "
                "reason=excluded.reason, updated_at=CURRENT_TIMESTAMP",
                (name, 1 if met else 0, reason),
            )

    def all_exit_criteria_met(self) -> tuple[bool, list[str]]:
        rows = self._conn.execute("SELECT name, met FROM exit_criteria").fetchall()
        unmet = [r["name"] for r in rows if not r["met"]]
        return (len(unmet) == 0, unmet)

    def exit_criteria_dict(self) -> dict[str, bool]:
        rows = self._conn.execute("SELECT name, met FROM exit_criteria").fetchall()
        return {r["name"]: bool(r["met"]) for r in rows}

    # ── agent notes (memory-tool backend) ───────────────────────────────────

    def note_write(self, agent: str, path: str, content: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO agent_notes (agent, path, content) VALUES (?, ?, ?) "
                "ON CONFLICT(agent, path) DO UPDATE SET content=excluded.content, "
                "updated_at=CURRENT_TIMESTAMP",
                (agent, path, content),
            )

    def note_read(self, agent: str, path: str) -> str | None:
        r = self._conn.execute(
            "SELECT content FROM agent_notes WHERE agent = ? AND path = ?",
            (agent, path),
        ).fetchone()
        return r["content"] if r else None

    def note_list(self, agent: str) -> list[str]:
        return [
            r["path"] for r in self._conn.execute(
                "SELECT path FROM agent_notes WHERE agent = ? ORDER BY path", (agent,)
            ).fetchall()
        ]

    # ── orchestrator state ──────────────────────────────────────────────────

    def save_orchestrator_state(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO orchestrator_state (key, value) VALUES (?, ?)",
                (key, value),
            )

    def latest_orchestrator_state(self, key: str) -> str | None:
        r = self._conn.execute(
            "SELECT value FROM orchestrator_state WHERE key = ? "
            "ORDER BY ts DESC LIMIT 1", (key,),
        ).fetchone()
        return r["value"] if r else None

    # ── tool audit ──────────────────────────────────────────────────────────

    def record_tool_call(
        self, agent: str, tool: str, args: dict, result_summary: str,
        result_path: str | None = None, duration_ms: int | None = None,
    ) -> None:
        args_json = json.dumps(args, default=str)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()[:16]
        with self.tx() as c:
            c.execute(
                """INSERT INTO tool_audit
                   (agent, tool, args_hash, args_json, result_summary,
                    result_path, duration_ms)
                   VALUES (?,?,?,?,?,?,?)""",
                (agent, tool, args_hash, args_json, result_summary,
                 result_path, duration_ms),
            )

    # ── scan meta ───────────────────────────────────────────────────────────

    def set_meta(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO scan_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str) -> str | None:
        r = self._conn.execute(
            "SELECT value FROM scan_meta WHERE key = ?", (key,)
        ).fetchone()
        return r["value"] if r else None

    # ── high-level status (for hooks) ──────────────────────────────────────

    def status_summary(self) -> dict:
        c = self._conn
        return {
            "phase": self.get_meta("current_phase") or "unknown",
            "hypotheses_pending": c.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status = 'pending'"
            ).fetchone()[0],
            "hypotheses_validating": c.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status = 'validating'"
            ).fetchone()[0],
            "hypotheses_confirmed": c.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status = 'confirmed'"
            ).fetchone()[0],
            "hypotheses_refuted": c.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status = 'refuted'"
            ).fetchone()[0],
            "findings_critical": c.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = 'critical'"
            ).fetchone()[0],
            "findings_high": c.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = 'high'"
            ).fetchone()[0],
            "findings_medium": c.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = 'medium'"
            ).fetchone()[0],
            "findings_low": c.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = 'low'"
            ).fetchone()[0],
            "primitives": c.execute("SELECT COUNT(*) FROM primitives").fetchone()[0],
            "primitives_unexplored": self.unexplored_primitive_count(),
            "chains": c.execute("SELECT COUNT(*) FROM chains").fetchone()[0],
            "observations": c.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            "capabilities": c.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0],
            "weird_compositions": c.execute(
                "SELECT COUNT(*) FROM weird_compositions"
            ).fetchone()[0],
            "flow_paths": c.execute("SELECT COUNT(*) FROM flow_paths").fetchone()[0],
            "coverage_gaps": c.execute(
                "SELECT COUNT(*) FROM coverage_gaps"
            ).fetchone()[0],
            "exit_criteria": self.exit_criteria_dict(),
        }

    # ── observations (cross-hunter shared board) ────────────────────────────

    def add_observation(self, o: Observation) -> str:
        with self.tx() as c:
            c.execute(
                """INSERT INTO observations
                   (id, author_agent, kind, repo, file, line, summary,
                    detail_md, affects_shapes)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (o.id, o.author_agent, o.kind, o.repo, o.file, o.line,
                 o.summary, o.detail_md, ",".join(o.affects_shapes)),
            )
        self.append_event(o.author_agent, "observation_added", asdict(o))
        return o.id

    def list_observations(
        self, kind: str | None = None, shape: str | None = None, repo: str | None = None,
    ) -> list[dict]:
        q = "SELECT * FROM observations WHERE 1=1"
        args: list[Any] = []
        if kind:
            q += " AND kind = ?"
            args.append(kind)
        if shape:
            q += " AND affects_shapes LIKE ?"
            args.append(f"%{shape}%")
        if repo:
            q += " AND repo = ?"
            args.append(repo)
        q += " ORDER BY updated_at DESC"
        return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    def increment_observation_seen(self, oid: str) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE observations SET seen_count = seen_count + 1, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?", (oid,),
            )

    # ── gadgets ─────────────────────────────────────────────────────────────

    def seed_gadgets(self, gadgets: list[Gadget]) -> None:
        with self.tx() as c:
            for g in gadgets:
                c.execute(
                    """INSERT OR REPLACE INTO gadgets
                       (id, language, library, version_range, gadget_name,
                        impact, notes_md, poc_template, references_json)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (g.id, g.language, g.library, g.version_range,
                     g.gadget_name, g.impact, g.notes_md, g.poc_template,
                     json.dumps(g.references)),
                )

    def query_gadgets(
        self, language: str, library: str | None = None,
    ) -> list[dict]:
        if library:
            rows = self._conn.execute(
                "SELECT * FROM gadgets WHERE language = ? AND library = ?",
                (language, library),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM gadgets WHERE language = ?", (language,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── capabilities (trust shadow) ─────────────────────────────────────────

    def add_capability(self, cap: Capability) -> str:
        with self.tx() as c:
            c.execute(
                """INSERT INTO capabilities
                   (id, asset_kind, asset_name, holder_repo, grants_json)
                   VALUES (?,?,?,?,?)""",
                (cap.id, cap.asset_kind, cap.asset_name, cap.holder_repo,
                 json.dumps(cap.grants)),
            )
        return cap.id

    def add_capability_edge(
        self, from_repo: str, to_capability: str, relationship: str,
        detail: str | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO capability_edges
                   (from_repo, to_capability, relationship, detail)
                   VALUES (?,?,?,?)""",
                (from_repo, to_capability, relationship, detail),
            )

    def list_capabilities(self) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM capabilities"
            ).fetchall()
        ]

    def list_capability_edges(self) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM capability_edges"
            ).fetchall()
        ]

    # ── weird compositions ─────────────────────────────────────────────────

    def add_weird_composition(self, w: WeirdComposition) -> str:
        with self.tx() as c:
            c.execute(
                """INSERT INTO weird_compositions
                   (id, primitive_ids, intended_use, unintended_use,
                    enables_goal, confidence)
                   VALUES (?,?,?,?,?,?)""",
                (w.id, json.dumps(w.primitive_ids), w.intended_use,
                 w.unintended_use, w.enables_goal, w.confidence),
            )
        return w.id

    def list_weird_compositions(self) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM weird_compositions ORDER BY confidence DESC"
            ).fetchall()
        ]

    # ── minimal repros ─────────────────────────────────────────────────────

    def set_minimal_repro(
        self, finding_id: str, minimal_payload: str,
        minimization_steps: list[dict] | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO minimal_repros
                   (finding_id, minimal_payload, minimization_steps_json)
                   VALUES (?,?,?)""",
                (finding_id, minimal_payload,
                 json.dumps(minimization_steps or [])),
            )

    def get_minimal_repro(self, finding_id: str) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM minimal_repros WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        return dict(r) if r else None

    def findings_lacking_minimal_repros(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT f.id FROM findings f "
            "LEFT JOIN minimal_repros m ON m.finding_id = f.id "
            "WHERE m.finding_id IS NULL"
        ).fetchall()
        return [r[0] for r in rows]

    # ── coverage gaps ──────────────────────────────────────────────────────

    def add_coverage_gap(
        self, surface: str, reason: str, suggested_action: str | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO coverage_gaps
                   (surface, reason, suggested_action)
                   VALUES (?,?,?)""",
                (surface, reason, suggested_action),
            )

    def list_coverage_gaps(self) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM coverage_gaps ORDER BY created_at"
            ).fetchall()
        ]

    # ── reachability cache ────────────────────────────────────────────────

    def cache_reachability(
        self, repo: str, from_fn: str, to_fn: str, reachable: bool,
        path: list[str] | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO reachability_cache
                   (repo, from_function, to_function, reachable, path_json)
                   VALUES (?,?,?,?,?)""",
                (repo, from_fn, to_fn, 1 if reachable else 0,
                 json.dumps(path) if path else None),
            )

    def lookup_reachability(
        self, repo: str, from_fn: str, to_fn: str,
    ) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM reachability_cache "
            "WHERE repo = ? AND from_function = ? AND to_function = ?",
            (repo, from_fn, to_fn),
        ).fetchone()
        return dict(r) if r else None

    # ── flow paths ────────────────────────────────────────────────────────

    def add_flow_path(self, fp: FlowPath) -> str:
        with self.tx() as c:
            c.execute(
                """INSERT INTO flow_paths
                   (id, repo, source_kind, sink_kind, path_json,
                    sanitizers_crossed_json, confidence)
                   VALUES (?,?,?,?,?,?,?)""",
                (fp.id, fp.repo, fp.source_kind, fp.sink_kind,
                 json.dumps(fp.path),
                 json.dumps(fp.sanitizers_crossed), fp.confidence),
            )
        return fp.id

    def list_flow_paths(self, repo: str | None = None) -> list[dict]:
        if repo:
            rows = self._conn.execute(
                "SELECT * FROM flow_paths WHERE repo = ?", (repo,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM flow_paths"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── v3: precision findings ─────────────────────────────────────────────

    def add_precision_finding(
        self, kind: str, repo: str, file: str, line: int,
        function_qual: str | None, cwe: str | None,
        detail_md: str, evidence: dict, confidence: float,
        cve_hint: str | None = None,
    ) -> str:
        pf_id = f"pf-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO precision_findings
                   (id, kind, repo, file, line, function_qual, cwe,
                    detail_md, evidence_json, confidence, cve_hint)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (pf_id, kind, repo, file, line, function_qual, cwe,
                 detail_md, json.dumps(evidence), confidence, cve_hint),
            )
        return pf_id

    def list_precision_findings(
        self, kind: str | None = None, repo: str | None = None,
        unconsumed_only: bool = False,
    ) -> list[dict]:
        q = "SELECT * FROM precision_findings WHERE 1=1"
        args: list[Any] = []
        if kind:
            q += " AND kind = ?"
            args.append(kind)
        if repo:
            q += " AND repo = ?"
            args.append(repo)
        if unconsumed_only:
            q += " AND consumed_by_hyp IS NULL"
        q += " ORDER BY confidence DESC"
        return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    def mark_precision_finding_consumed(self, pf_id: str, hyp_id: str) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE precision_findings SET consumed_by_hyp = ? WHERE id = ?",
                (hyp_id, pf_id),
            )

    # ─── v3: sanitizer builds ───────────────────────────────────────────────

    def record_sanitizer_build(
        self, repo: str, git_sha: str, sanitizers: str,
        build_system: str | None, status: str,
        build_log_path: str | None, binaries: list[dict],
        warnings: list[dict], duration_s: int,
    ) -> str:
        sb_id = f"sb-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO sanitizer_builds
                   (id, repo, git_sha, sanitizers, build_system, status,
                    build_log_path, binaries_json, warnings_json, duration_s)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (sb_id, repo, git_sha, sanitizers, build_system, status,
                 build_log_path, json.dumps(binaries), json.dumps(warnings),
                 duration_s),
            )
        return sb_id

    def latest_sanitizer_build(
        self, repo: str, git_sha: str, sanitizers: str = "asan,ubsan",
    ) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM sanitizer_builds "
            "WHERE repo = ? AND git_sha = ? AND sanitizers = ? "
            "ORDER BY started_at DESC LIMIT 1",
            (repo, git_sha, sanitizers),
        ).fetchone()
        return dict(r) if r else None

    # ─── v3: fuzz runs and crashes ──────────────────────────────────────────

    def record_fuzz_run(
        self, repo: str, function_qual: str, binary_path: str,
        timeout_s: int, executions: int | None, coverage_pct: float | None,
        status: str, triggered_by: str | None, duration_s: int,
        crashes: list[dict] | None = None,
    ) -> str:
        """Record a fuzz run and (atomically) any crashes it discovered.

        Pass ``crashes=[{"asan_kind": ..., "crash_stack": [...], "input_path":
        ..., "minimized_input_path": ..., "asan_log_path": ...}, ...]`` to
        insert the run and the crashes in a single transaction.
        """
        fr_id = f"fr-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO fuzz_runs
                   (id, repo, function_qual, binary_path, timeout_s,
                    executions, coverage_pct, status, triggered_by, duration_s)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (fr_id, repo, function_qual, binary_path, timeout_s,
                 executions, coverage_pct, status, triggered_by, duration_s),
            )
            for crash in (crashes or []):
                c.execute(
                    """INSERT INTO fuzz_crashes
                       (id, fuzz_run_id, asan_kind, crash_stack_json,
                        input_path, minimized_input_path, asan_log_path)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        f"fc-{_rand_id()}", fr_id,
                        crash.get("asan_kind"),
                        json.dumps(crash.get("crash_stack", [])),
                        crash.get("input_path", ""),
                        crash.get("minimized_input_path"),
                        crash.get("asan_log_path"),
                    ),
                )
        return fr_id

    def record_fuzz_crash(
        self, fuzz_run_id: str, asan_kind: str | None,
        crash_stack: list[str], input_path: str,
        minimized_input_path: str | None, asan_log_path: str | None,
    ) -> str:
        """Record a crash for an *existing* fuzz run.

        Prefer the ``crashes=`` kwarg on :py:meth:`record_fuzz_run` when the
        crashes are discovered as part of the same run — that path is atomic.
        """
        c_id = f"fc-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO fuzz_crashes
                   (id, fuzz_run_id, asan_kind, crash_stack_json,
                    input_path, minimized_input_path, asan_log_path)
                   VALUES (?,?,?,?,?,?,?)""",
                (c_id, fuzz_run_id, asan_kind, json.dumps(crash_stack),
                 input_path, minimized_input_path, asan_log_path),
            )
        return c_id

    def list_fuzz_crashes(self, fuzz_run_id: str | None = None) -> list[dict]:
        if fuzz_run_id:
            rows = self._conn.execute(
                "SELECT * FROM fuzz_crashes WHERE fuzz_run_id = ?",
                (fuzz_run_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM fuzz_crashes ORDER BY discovered_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def list_fuzz_runs_for_function(
        self, repo: str, function_qual: str,
    ) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM fuzz_runs WHERE repo = ? AND function_qual = ? "
            "ORDER BY started_at DESC",
            (repo, function_qual),
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── v3: patch rules ────────────────────────────────────────────────────

    def add_patch_rule(
        self, source_kind: str, source_ref: str, repo: str | None,
        bug_class: str | None, rule_yaml: str,
        before_pattern: str | None, after_pattern: str | None,
        essence_md: str | None, confidence: float,
    ) -> str:
        pr_id = f"pr-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO patch_rules
                   (id, source_kind, source_ref, repo, bug_class,
                    rule_yaml, before_pattern, after_pattern,
                    essence_md, confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (pr_id, source_kind, source_ref, repo, bug_class,
                 rule_yaml, before_pattern, after_pattern,
                 essence_md, confidence),
            )
        return pr_id

    def list_patch_rules(
        self, source_kind: str | None = None, repo: str | None = None,
    ) -> list[dict]:
        q = "SELECT * FROM patch_rules WHERE 1=1"
        args: list[Any] = []
        if source_kind:
            q += " AND source_kind = ?"
            args.append(source_kind)
        if repo:
            q += " AND repo = ?"
            args.append(repo)
        q += " ORDER BY confidence DESC"
        return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    def get_patch_rule(self, pr_id: str) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM patch_rules WHERE id = ?", (pr_id,),
        ).fetchone()
        return dict(r) if r else None

    # ─── v3: variant links ──────────────────────────────────────────────────

    def add_variant_link(
        self, child_hyp_id: str, parent_finding_id: str,
        propagation_rule_id: str | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO variant_links
                   (child_hyp_id, parent_finding_id, propagation_rule_id)
                   VALUES (?,?,?)""",
                (child_hyp_id, parent_finding_id, propagation_rule_id),
            )

    def list_variants_of(self, parent_finding_id: str) -> list[dict]:
        return [
            dict(r) for r in self._conn.execute(
                "SELECT * FROM variant_links WHERE parent_finding_id = ?",
                (parent_finding_id,),
            ).fetchall()
        ]

    # ─── v3: dependency catalog ─────────────────────────────────────────────

    def record_dependencies(
        self, repo: str, deps: list[dict[str, Any]],
    ) -> int:
        """Bulk-record dependencies for ``repo``. Idempotent (UPSERT on uniq)."""
        if not deps:
            return 0
        rows = [
            (
                repo,
                str(d.get("manifest") or ""),
                str(d.get("ecosystem") or ""),
                str(d.get("name") or ""),
                (d.get("version") or "") or None,
                str(d.get("scope") or "runtime"),
            )
            for d in deps
            if d.get("name")
        ]
        with self.tx() as c:
            c.executemany(
                """INSERT OR IGNORE INTO dependencies
                   (repo, manifest, ecosystem, name, version, scope)
                   VALUES (?,?,?,?,?,?)""",
                rows,
            )
        return len(rows)

    def dependency_versions(self, repo: str) -> dict[str, str]:
        """Return ``{name: version}`` for the given repo, only entries with
        a version set. Used by precision tools as a recon hint.
        """
        rows = self._conn.execute(
            "SELECT name, version FROM dependencies "
            "WHERE repo = ? AND version IS NOT NULL AND version != '' LIMIT 5000",
            (repo,),
        ).fetchall()
        return {r["name"]: r["version"] for r in rows}

    # ─── v3: hook tool-call ledger ──────────────────────────────────────────

    def record_hook_tool_call(self, agent: str, tool: str) -> None:
        """Append a row for the pre_tool_use_gate rate limiter."""
        with self.tx() as c:
            c.execute(
                "INSERT INTO hook_tool_calls (agent, tool) VALUES (?, ?)",
                (agent, tool),
            )

    def count_hook_tool_calls(
        self, agent: str, window_seconds: int,
    ) -> int:
        """Count this agent's tool calls in the last ``window_seconds``."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM hook_tool_calls "
            "WHERE agent = ? "
            "AND ts >= datetime('now', ?)",
            (agent, f"-{int(window_seconds)} seconds"),
        ).fetchone()
        return int(row["n"]) if row else 0

    # ─── Phase 2: adversary verdicts ────────────────────────────────────────

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
        """Persist one adversary verdict for a finding.

        Multiple verdicts may be recorded for the same finding — for
        instance the two-adversary mode records one verdict per
        adversary. The Stop hook checks that *at least one* verdict
        exists for every confirmed finding.
        """
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO adversary_verdicts "
                "(finding_id, adversary, verdict, argument_for, "
                " argument_against, reasoning, evidence_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    finding_id, adversary, verdict, argument_for,
                    argument_against, reasoning,
                    json.dumps(evidence) if evidence else None,
                ),
            )
        self.append_event(adversary, "adversary_verdict", {
            "finding_id": finding_id,
            "verdict": verdict,
            "reasoning": (reasoning or "")[:500],
        })
        return int(cur.lastrowid or 0)

    def list_adversary_verdicts(
        self, finding_id: str | None = None,
    ) -> list[dict]:
        """Return all adversary verdicts, optionally filtered to one finding."""
        if finding_id:
            rows = self._conn.execute(
                "SELECT * FROM adversary_verdicts "
                "WHERE finding_id = ? ORDER BY id",
                (finding_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM adversary_verdicts ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]

    def findings_missing_adversary_verdict(self) -> list[str]:
        """IDs of findings that have no verdict yet.

        The Stop hook calls this and refuses the stop if any are
        present. Every confirmed finding must have at least one
        adversary verdict before the orchestrator can stop.
        """
        rows = self._conn.execute(
            "SELECT f.id FROM findings f "
            "LEFT JOIN adversary_verdicts v ON v.finding_id = f.id "
            "GROUP BY f.id HAVING COUNT(v.id) = 0"
        ).fetchall()
        return [r["id"] for r in rows]

    def record_chain_adversary_verdict(
        self,
        chain_id: str,
        adversary: str,
        verdict: str,
        reasoning: str | None = None,
    ) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO chain_adversary_verdicts "
                "(chain_id, adversary, verdict, reasoning) "
                "VALUES (?,?,?,?)",
                (chain_id, adversary, verdict, reasoning),
            )
        return int(cur.lastrowid or 0)

    def list_chain_adversary_verdicts(
        self, chain_id: str | None = None,
    ) -> list[dict]:
        if chain_id:
            rows = self._conn.execute(
                "SELECT * FROM chain_adversary_verdicts "
                "WHERE chain_id = ? ORDER BY id", (chain_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM chain_adversary_verdicts ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── v3: differential findings ──────────────────────────────────────────

    def add_differential_finding(
        self, protocol: str, input_hex: str, parser_results: dict,
        divergence: bool, exploit_class: str | None,
    ) -> str:
        df_id = f"df-{_rand_id()}"
        with self.tx() as c:
            c.execute(
                """INSERT INTO differential_findings
                   (id, protocol, input_hex, parser_results_json,
                    divergence, exploit_class)
                   VALUES (?,?,?,?,?,?)""",
                (df_id, protocol, input_hex, json.dumps(parser_results),
                 1 if divergence else 0, exploit_class),
            )
        return df_id


def open_kg(path: str | Path | None = None) -> KG:
    """Open the KG at the path given by LACUNA_KG_PATH (default), or override."""
    import os
    db_path = path or os.environ.get("LACUNA_KG_PATH", "/state/lacuna.db")
    return KG(db_path)
