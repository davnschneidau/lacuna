# Invariants

The load-bearing properties Lacuna's tests, hooks, and CI lints
enforce.

Each invariant has:

- A unique ID (e.g. `INV-001`) so the relevant test can name it in
  its docstring.
- A one-line statement.
- A list of *enforcing artifacts* (test files, lint scripts, hooks).

If you propose a change that breaks an invariant, you must either
(a) explicitly remove the invariant in the same PR with a paragraph
explaining why it no longer applies, or (b) extend the invariant to
accommodate the new shape. Silent regressions are caught by the
enforcing artifacts.

---

## INV-001 — Single version source of truth

**Statement.** `src/lacuna/__init__.py:__version__` is the only place
in the repository where the Lacuna version is canonically declared.
Every other file that needs the version reads it from there or
declares the same literal; no two declarations may disagree.

**Enforcing artifacts.**

- `scripts/lint_versions.py` (run in CI).
- `tests/test_repo_policy.py::test_lint_versions_script_passes`.
- `pyproject.toml` uses `dynamic = ["version"]`.

## INV-002 — SAST kind never sees DAST tools

**Statement.** When `scan_kind` is `sast`, no `lacuna-dast.*` tool
may be advertised to the agent (via `.mcp.json`), spawned (via
`.claude/topology.yaml`), or invoked (via the PreToolUse and the
DAST server kind-guard). The diff scope counts as SAST — the
`LACUNA_MODE=diff` historical exemption is closed.

**Enforcing artifacts.**

- `lacuna.kind.parse_legacy_mode` (taxonomy).
- `lacuna.harness.workspace._write_mcp_config` (omits dast server).
- `lacuna.hooks.pre_session_validate` (refuses inconsistent config).
- `lacuna.hooks.pre_tool_use_gate` (denies dast tool calls).
- `lacuna.tools.dast_server._kind_guard` (refuses every tool call).
- `tests/test_kind_taxonomy.py`.
- `tests/test_sast_dast_separation.py`.

## INV-003 — Every confirmed finding has an adversary verdict

**Statement.** The Stop hook refuses to allow the orchestrator to
finish a scan while any row in `findings` lacks at least one
matching row in `adversary_verdicts`. The default adversary verdict
when one is recorded is `refute_pending`; the adversary must
actively transition to `confirmed`, `downgrade`, `refuted`, or
`needs_human`.

**Enforcing artifacts.**

- `KG.findings_missing_adversary_verdict` (query).
- `lacuna.hooks.stop_continuation` (blocks).
- `tests/test_adversary.py::test_stop_hook_blocks_on_missing_adversary_verdicts`.

## INV-004 — Drafts are promoted only from trusted regions

**Statement.** The PreCompact flush hook accepts `<hypothesis-draft>`,
`<primitive-draft>`, and `<chain-candidate>` tags only when they
appear inside an `<assistant-draft>` (or equivalent agent-authored)
region of the transcript. Tags appearing inside `<tool-result>`,
`<dast-response>`, `<http-response>`, or `<user-message>` regions
are refused and counted in the `precompact_injection_attempt`
event.

**Enforcing artifacts.**

- `lacuna.hooks.pre_compact_flush._trusted_transcript`.
- `tests/test_hooks.py::test_precompact_flush_refuses_drafts_inside_dast_response`.

## INV-005 — Rate limit denies; it never silently sleeps

**Statement.** The PreToolUse hook returns `{"decision": "deny",
"retry_after_s": …}` when an agent exceeds the manifest rate limit
in the rolling 1-second window. It MUST NOT `time.sleep` and then
return `allow` — that lets the over-budget call land on the target
anyway.

**Enforcing artifacts.**

- `lacuna.hooks.pre_tool_use_gate` (the body of the rate-limit branch).
- `tests/test_hooks.py::test_pretooluse_rate_limit_denies_then_retry`.

## INV-006 — Migrations run in numeric order, exactly once each

**Statement.** Every entry in `lacuna.kg.migrations.MIGRATIONS`
has a unique strictly-monotonically-increasing `id`. Gaps are
forbidden. The runner records each application in
`schema_migrations` and never re-applies a recorded id. Failing a
migration rolls back its statements and re-raises; the partial DB
must not contain the failed migration's id.

**Enforcing artifacts.**

- `lacuna.kg.migrations.apply_pending`.
- `tests/test_kg_migrations_protocol.py::test_migrations_apply_in_order_on_fresh_db`.
- `tests/test_kg_migrations_protocol.py::test_migrations_are_idempotent_across_open`.

## INV-007 — KGProtocol surface is implemented by both KG and MockKG

**Statement.** Every method declared on `KGProtocol` MUST be
implemented by both `KG` (production) and `MockKG` (tests). Adding
a method to the protocol without implementing it on either causes
`isinstance(kg, KGProtocol)` runtime checks to fail; CI enforces
this via the protocol tests.

**Enforcing artifacts.**

- `lacuna.kg.protocol.KGProtocol`.
- `lacuna.kg.mock.MockKG`.
- `tests/test_kg_migrations_protocol.py::test_kg_satisfies_protocol`.
- `tests/test_kg_migrations_protocol.py::test_mock_kg_satisfies_protocol`.

## INV-008 — Every agent file is classified in topology.yaml

**Statement.** For every `.claude/agents/*.md` file there is exactly
one entry in one of the four lists in `.claude/topology.yaml`
(`shared` / `sast_only` / `dast_only` / `either`). Topology entries
referencing missing files, or files missing from topology, fail
the lint.

**Enforcing artifacts.**

- `scripts/lint_topology.py`.
- `tests/test_repo_policy.py::test_topology_lint_includes_adversary_agents`.

## INV-009 — Agent frontmatter and skill frontmatter conform to schema

**Statement.** Every `.claude/agents/*.md` file declares
`name`, `description`, and `model` in its YAML frontmatter; the
`model` value matches the `${LACUNA_MODEL_TIER:-default}` pattern;
the `name` matches the filename stem; and any declared `tools` use
the allowed prefixes. Every `.claude/skills/*/SKILL.md` declares
`name`, `description`, and `when_to_use` per
`docs/skill-schema.md`.

**Enforcing artifacts.**

- `scripts/lint_agents.py`.
- `scripts/lint_docs.py` (skill frontmatter section).
- `docs/skill-schema.md` (the contract).
- `tests/test_repo_policy.py::test_lint_agents_script_passes`.
- `tests/test_repo_policy.py::test_lint_docs_script_passes`.
- `tests/test_repo_policy.py::test_every_skill_has_when_to_use`.

## INV-010 — Documentation code fences declare a language

**Statement.** Every fenced code block under `docs/` and
`.claude/skills/` declares a language tag on the opening fence
(use `text` for plain ASCII content). This keeps the doc-as-test
pass from silently skipping blocks and lets reviewers spot
mis-formatted code at a glance.

**Enforcing artifacts.**

- `scripts/lint_docs.py` (code-fence language check).
- `tests/test_repo_policy.py::test_lint_docs_script_passes`.
