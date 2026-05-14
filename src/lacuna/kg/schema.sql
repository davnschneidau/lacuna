-- Lacuna knowledge graph schema. SQLite. Ephemeral per scan.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- ───────────────────────────────────────────────────────────────────────────
-- Event log — append-only durable record of the entire scan.
-- The session is NOT the model's context window. The event log is.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS event_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    agent           TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    parent_event_id INTEGER REFERENCES event_log(id)
);
CREATE INDEX IF NOT EXISTS idx_event_agent_ts ON event_log(agent, ts);
CREATE INDEX IF NOT EXISTS idx_event_type_ts  ON event_log(event_type, ts);

-- ───────────────────────────────────────────────────────────────────────────
-- Application model (from Recon)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS application_model (
    id              INTEGER PRIMARY KEY,
    summary_md      TEXT NOT NULL,
    facts_json      TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Hypotheses (a claim awaiting validation)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hypotheses (
    id                 TEXT PRIMARY KEY,
    hunter             TEXT NOT NULL,
    shape              TEXT NOT NULL,
    repo               TEXT,
    file               TEXT,
    line               INTEGER,
    description        TEXT NOT NULL,
    attacker_scenario  TEXT,
    confidence         REAL NOT NULL,
    status             TEXT NOT NULL CHECK (status IN
                       ('pending','validating','confirmed','refuted','needs_human')),
    refutation_reason  TEXT,
    finding_id         TEXT,
    seen_by            TEXT,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hyp_status  ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hyp_shape   ON hypotheses(shape, repo, file);

-- ───────────────────────────────────────────────────────────────────────────
-- Findings (confirmed hypotheses)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    hypothesis_id       TEXT REFERENCES hypotheses(id),
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN
                        ('low','medium','high','critical')),
    cvss_vector         TEXT,
    cwes                TEXT,
    repos_involved      TEXT,
    validator_summary   TEXT NOT NULL,
    remediation_md      TEXT,
    validated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);

-- ───────────────────────────────────────────────────────────────────────────
-- Evidence (attachments to findings)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT REFERENCES findings(id),
    kind            TEXT NOT NULL,
    payload_path    TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Primitives (capabilities derived from confirmed findings)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS primitives (
    id                  TEXT PRIMARY KEY,
    finding_id          TEXT REFERENCES findings(id),
    name                TEXT NOT NULL,
    description         TEXT NOT NULL,
    prerequisites_json  TEXT NOT NULL,
    effects_json        TEXT NOT NULL,
    repos_involved      TEXT NOT NULL,
    chain_explored      INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Chain candidates (work-in-progress chains, may be abandoned)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chain_candidates (
    id                  TEXT PRIMARY KEY,
    primitive_ids_json  TEXT NOT NULL,
    goal                TEXT NOT NULL,
    narrative_so_far    TEXT,
    status              TEXT NOT NULL DEFAULT 'exploring',
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Chains (confirmed compositions)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chains (
    id                  TEXT PRIMARY KEY,
    primitive_ids_json  TEXT NOT NULL,
    goal                TEXT NOT NULL CHECK (goal IN
                        ('rce','data-exfil','financial-loss','priv-esc',
                         'account-takeover','denial-of-service','full-compromise')),
    combined_severity   TEXT NOT NULL,
    narrative_md        TEXT NOT NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Exit criteria — checked by the Stop hook to decide whether the scan is done
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS exit_criteria (
    name        TEXT PRIMARY KEY,
    met         INTEGER NOT NULL DEFAULT 0,
    reason      TEXT,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO exit_criteria (name, met) VALUES
    ('application_model_ready', 0),
    ('all_hunters_returned', 0),
    ('all_hypotheses_resolved', 0),
    ('chain_search_exhausted', 0),
    ('reports_generated', 0);

-- ───────────────────────────────────────────────────────────────────────────
-- Tool audit log
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tool_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    agent           TEXT NOT NULL,
    tool            TEXT NOT NULL,
    args_hash       TEXT NOT NULL,
    args_json       TEXT NOT NULL,
    result_summary  TEXT,
    result_path     TEXT,
    duration_ms     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON tool_audit(agent, ts);
CREATE INDEX IF NOT EXISTS idx_audit_tool  ON tool_audit(tool, ts);

-- ───────────────────────────────────────────────────────────────────────────
-- Per-agent scratch notes (memory tool backend)
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_notes (
    agent       TEXT NOT NULL,
    path        TEXT NOT NULL,
    content     TEXT NOT NULL,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent, path)
);

-- ───────────────────────────────────────────────────────────────────────────
-- Orchestrator state — survives compaction via PreCompact hook flush
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS orchestrator_state (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL
);

-- ───────────────────────────────────────────────────────────────────────────
-- Scan metadata
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- ───────────────────────────────────────────────────────────────────────────
-- Cross-hunter shared observation board.
-- Facts hunters discover that other hunters might find useful. Recalibrates
-- confidence across the swarm without forcing tight coupling.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS observations (
    id              TEXT PRIMARY KEY,
    author_agent    TEXT NOT NULL,
    kind            TEXT NOT NULL,
    -- canonical kinds:
    --   middleware_bypass     (header X bypasses middleware Y)
    --   sanitizer_bypass      (sanitizer X is bypassable via Y)
    --   framework_quirk       (framework X does Y by default)
    --   secret_location       (secret X is at location Y)
    --   trust_boundary_hole   (boundary X has hole at Y)
    --   shared_state          (resource X is shared across services)
    --   reachability_fact     (function X is reachable from Y)
    --   library_gadget        (library X gadget chain Y exists)
    repo            TEXT,
    file            TEXT,
    line            INTEGER,
    summary         TEXT NOT NULL,
    detail_md       TEXT,
    affects_shapes  TEXT,            -- comma-list of shapes this is relevant to
    seen_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_obs_kind ON observations(kind);
CREATE INDEX IF NOT EXISTS idx_obs_shapes ON observations(affects_shapes);

-- ───────────────────────────────────────────────────────────────────────────
-- Known-gadget catalog (library + version range → exploit chain).
-- Pre-seeded at scan start; queryable by validators and chain-builder.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gadgets (
    id              TEXT PRIMARY KEY,
    language        TEXT NOT NULL,
    library         TEXT NOT NULL,
    version_range   TEXT NOT NULL,    -- semver-ish range string
    gadget_name     TEXT NOT NULL,
    impact          TEXT NOT NULL,    -- rce | deserialize | ssrf | etc
    notes_md        TEXT,
    poc_template    TEXT,             -- minimal payload template, $TOKENS replaced at use
    references_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_gadget_lib ON gadgets(language, library);

-- ───────────────────────────────────────────────────────────────────────────
-- Trust-shadow capability graph.
-- For every credential, secret, key — who can read, use, sign, authorize.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS capabilities (
    id              TEXT PRIMARY KEY,
    asset_kind      TEXT NOT NULL,    -- secret | key | token_signing_key | iam_role | db_creds | etc
    asset_name      TEXT NOT NULL,
    holder_repo     TEXT NOT NULL,    -- which service holds it
    grants_json     TEXT NOT NULL,    -- list of "can:read X / sign Y / call Z"
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS capability_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    from_repo       TEXT NOT NULL,
    to_capability   TEXT NOT NULL REFERENCES capabilities(id),
    relationship    TEXT NOT NULL,    -- reads | uses | trusts | inherits | signs_for
    detail          TEXT
);

-- ───────────────────────────────────────────────────────────────────────────
-- Weird-machine compositions: unintended computations enabled by primitives.
-- Used by chain-builder to think laterally.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weird_compositions (
    id              TEXT PRIMARY KEY,
    primitive_ids   TEXT NOT NULL,    -- json list
    intended_use    TEXT,             -- what each primitive was supposed to do
    unintended_use  TEXT NOT NULL,    -- the weird-machine outcome
    enables_goal    TEXT,
    confidence      REAL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Minimal repro: smallest reproducing payload per finding.
-- The validator must produce one before stop.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS minimal_repros (
    finding_id      TEXT PRIMARY KEY REFERENCES findings(id),
    minimal_payload TEXT NOT NULL,
    minimization_steps_json TEXT,
    confirmed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Coverage gaps: surfaces we did NOT examine, and why.
-- Reported in the technical report as "negative space".
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS coverage_gaps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    surface         TEXT NOT NULL,    -- e.g. "graphql schema", "auth-svc:src/legacy/"
    reason          TEXT NOT NULL,    -- e.g. "no schema found", "wall-clock budget"
    suggested_action TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- Reachability cache: function-to-function reachability from prior queries.
-- Built incrementally by the call graph engine; cleared per scan.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reachability_cache (
    from_function   TEXT NOT NULL,
    to_function     TEXT NOT NULL,
    repo            TEXT NOT NULL,
    reachable       INTEGER NOT NULL,
    path_json       TEXT,
    computed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (repo, from_function, to_function)
);

-- ───────────────────────────────────────────────────────────────────────────
-- Data-flow paths discovered by the inter-procedural engine.
-- Persisted so the validator can reference them by ID.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flow_paths (
    id              TEXT PRIMARY KEY,
    repo            TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    sink_kind       TEXT NOT NULL,
    path_json       TEXT NOT NULL,    -- ordered list of {file, line, function, expr}
    sanitizers_crossed_json TEXT,
    confidence      REAL NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_flow_kinds ON flow_paths(source_kind, sink_kind);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Precision static analysis findings
-- Output from Layer 2 tools (integer range, UAF, format string, type confusion).
-- NOT hypotheses; high-quality leads that hunters convert into hypotheses.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS precision_findings (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,      -- int_overflow|uaf|double_free|fmt_string|type_confusion
    repo            TEXT NOT NULL,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    function_qual   TEXT,
    cwe             TEXT,
    detail_md       TEXT NOT NULL,
    evidence_json   TEXT,               -- structured analysis output
    confidence      REAL NOT NULL,
    cve_hint        TEXT,               -- forward-compat with Layer 1
    consumed_by_hyp TEXT,               -- hypothesis ID that uses this
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pf_kind ON precision_findings(kind);
CREATE INDEX IF NOT EXISTS idx_pf_repo ON precision_findings(repo);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Sanitizer build records
-- Memoizes expensive build attempts. Re-used by fuzzer + tests.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sanitizer_builds (
    id              TEXT PRIMARY KEY,
    repo            TEXT NOT NULL,
    git_sha         TEXT NOT NULL,
    sanitizers      TEXT NOT NULL,      -- e.g. "asan,ubsan"
    build_system    TEXT,               -- cmake|make|cargo|...
    status          TEXT NOT NULL,      -- success|failed|timeout
    build_log_path  TEXT,
    binaries_json   TEXT,               -- list of {name, path, kind}
    warnings_json   TEXT,               -- list of sanitizer warnings caught at build
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_s      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sb_repo ON sanitizer_builds(repo, git_sha);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Fuzz runs
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fuzz_runs (
    id              TEXT PRIMARY KEY,
    repo            TEXT NOT NULL,
    function_qual   TEXT NOT NULL,
    binary_path     TEXT NOT NULL,
    timeout_s       INTEGER NOT NULL,
    executions      INTEGER,
    coverage_pct    REAL,
    status          TEXT NOT NULL,      -- completed|timeout|build_failed|crashed
    triggered_by    TEXT,               -- hypothesis_id or "precision"
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_s      INTEGER
);

CREATE TABLE IF NOT EXISTS fuzz_crashes (
    id              TEXT PRIMARY KEY,
    fuzz_run_id     TEXT NOT NULL REFERENCES fuzz_runs(id),
    asan_kind       TEXT,               -- heap-buffer-overflow|use-after-free|null-deref|...
    crash_stack_json TEXT,
    input_path      TEXT NOT NULL,
    minimized_input_path TEXT,
    asan_log_path   TEXT,
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Patch-derived rules
-- The output of patch_essence: a semgrep-style rule extracted from a fix
-- commit. Used by propagate_pattern to find variants.
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS patch_rules (
    id              TEXT PRIMARY KEY,
    source_kind     TEXT NOT NULL,      -- internal_commit|cve|finding
    source_ref      TEXT NOT NULL,      -- commit_sha|cve_id|finding_id
    repo            TEXT,
    bug_class       TEXT,               -- CWE id
    rule_yaml       TEXT NOT NULL,      -- semgrep rule
    before_pattern  TEXT,
    after_pattern   TEXT,
    essence_md      TEXT,
    confidence      REAL NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Variant findings: hypotheses spawned from a parent finding
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS variant_links (
    child_hyp_id    TEXT PRIMARY KEY,
    parent_finding_id TEXT NOT NULL,
    propagation_rule_id TEXT REFERENCES patch_rules(id),
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ───────────────────────────────────────────────────────────────────────────
-- v3 — Differential parse results
-- ───────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS differential_findings (
    id              TEXT PRIMARY KEY,
    protocol        TEXT NOT NULL,
    input_hex       TEXT NOT NULL,
    parser_results_json TEXT NOT NULL,
    divergence      INTEGER NOT NULL,   -- bool
    exploit_class   TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
