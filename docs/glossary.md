# Glossary

A single-source-of-truth glossary so docs, agent prompts, and code
comments use the same word for the same concept. Every new noun
introduced to Lacuna belongs here; a PR that defines a term outside
this file fails `scripts/lint_docs.py`.

Terms are organised alphabetically. Cross-references use `*term*`.

---

**Adversary** — the successor to the *Skeptic*. Defaults to a
verdict of `refute_pending` (the finding must defend itself) rather
than `confirmed`. Two-adversary mode runs *Adversary-B* in parallel
and promotes the finding to `needs_human` on disagreement. See
`.claude/agents/adversary.md`.

**Adversary verdict** — one of: `confirmed`, `downgrade`, `refuted`,
`needs_human`, `refute_pending`. Persisted in `adversary_verdicts`
(per finding) or `chain_adversary_verdicts` (per chain). The Stop
hook refuses to finish a scan while any *finding* lacks an adversary
verdict; chain-level verdicts are recorded but not gated by Stop.

**Application model** — the structured summary recon produces about
the target application: repos, languages, frameworks, trust
boundaries, entry points. Lives in the `application_model` row of
the KG; cached after first read.

**Attack chain** — a composed sequence of *primitives* that produces
an end-to-end attacker outcome that is more severe than any single
constituent finding. Produced by the *Chain Builder* and reviewed
by the *Chain Adversary*.

**Bottom line** — the first paragraph of the executive report. Names
the most consequential outcome the scan found, in business language.

**CHAIN-ADVERSARY** — an adversary that reviews chains rather than
individual findings. Checks prerequisite/effect matching across
steps, primitive verdict status, attacker starting state, and
end-state significance.

**Chain Builder** — the agent that composes confirmed *primitives*
into *attack chains*. Runs incrementally (every 5 new primitives by
default).

**Confirmed finding** — a finding promoted from a *hypothesis* by the
validator's red/blue dialectic. Must subsequently receive at least
one adversary verdict before it can appear in the report.

**Counter-evidence** — concrete evidence cited by the *Adversary* in
support of a `refuted` or `downgrade` verdict (e.g. a reachability
query returning no path, a test asserting the safe behaviour, a
recent patch on the same line).

**DAST (Dynamic Application Security Testing)** — analysis that
exercises the running application (HTTP requests, fuzzing, OOB
callbacks, headless browser). In Lacuna, the
`lacuna-dast` MCP server provides the toolbelt. Available only when
`scan_kind=sast_dast` (Phase 1).

**Deep oracle** — a high-cost runtime tool that exists specifically
to confirm a single bug class with high precision: `sqlmap` for SQL
injection, `ysoserial` for .NET/Java deserialisation, `gopherus` for
SSRF, etc. Phase 5 wraps these in the *export adapters*.

**Disprove-first** — the load-bearing skill of the Phase 2 adversary
(`.claude/skills/disprove-first/`). Forces the reviewer to write an
*argument-against* the finding BEFORE reading the validator's notes,
inverting the historic "confirm unless I find a problem" default.

**Event log** — append-only table (`event_log`) that records every
agent decision, tool call, and KG mutation. Reporters read it for
narrative; auditors read it for forensics; the precompact hook
reads it during transcript compaction.

**Evidence** — file-system blobs (request/response traces, ASan logs,
PoC inputs) attached to a finding via the `evidence` table. The KG
stores only the path; the blob lives under `LACUNA_EVIDENCE_DIR`.

**Exit criterion** — a row in `exit_criteria` that must be met
(`met=1`) before the orchestrator's Stop hook permits the scan to
end. The default set is
`{application_model_ready, all_hunters_returned,
all_hypotheses_resolved, chain_search_exhausted, reports_generated}`
plus the Phase 2 implicit *adversary verdict coverage* check.

**Finding** — a confirmed hypothesis. Has a severity, a CWE, a
location, a validator summary, and (post-Phase-2) at least one
adversary verdict.

**Hypothesis** — a hunter's claim that a vulnerability *probably*
exists at a given location. Status transitions: `pending` →
`validating` → `confirmed` (with `finding_id`) | `refuted` (with
`refutation_reason`) | `needs_human`.

**Idempotency key** — a string (typically a payload hash) that
guarantees at-most-once-effect for a writer. Stored in
`idempotency_keys`; the writer calls `claim_idempotency_key` and
proceeds only if the call returns `True`.

**KG (Knowledge Graph)** — Lacuna's durable memory. SQLite database
under `LACUNA_KG_PATH` containing the application model, hypotheses,
findings, primitives, chains, observations, evidence, event log,
adversary verdicts, and meta. Survives compaction; agents
hydrate from it after every PreCompact.

**Kind (scan_kind)** — `sast` or `sast_dast`. Determines which MCP
servers are registered, which agents are recruited, and which report
sections render. Distinct from *scope*. See `lacuna.kind`.

**Manifest** — `app.lacuna.yaml`. Operator-authored YAML describing
the application: repos, trust boundaries, DAST safety policy,
entry points, business-critical functions.

**MCP server** — Model Context Protocol server that exposes
deterministic tools to the agent. Lacuna ships three: `lacuna-recon`
(SAST), `lacuna-kg` (read/write the KG), and `lacuna-dast` (only in
`scan_kind=sast_dast`).

**Migration** — a Phase 3 schema change. Defined in
`lacuna.kg.migrations.MIGRATIONS` as `(id, name, up_sql)` tuples;
applied in order by `apply_pending`. Idempotent; runs on every
`KG.initialize()`.

**Mock KG** — `lacuna.kg.mock.MockKG`. In-memory implementation of
`KGProtocol` for tests that don't need transactional guarantees.

**Mythos-style** — Anthropic-internal pattern of agentic
debugging/scanning that gave Lacuna its top-level architecture:
hypothesis-as-unit-of-work, durable KG, red/blue dialectic,
context-management discipline. Lacuna borrows the *behaviour*, not
the codebase.

**OOB callback** — out-of-band callback. A unique token registered
with an external collector (`interactsh.app`, `oobi.dev`, or
operator-hosted) so blind exploits (SSRF, deserialisation, log4j)
can be confirmed when the target hits the collector.

**Pre-compact flush** — the `pre_compact_flush.py` hook. Before
Claude Code compacts the transcript (i.e. loses context), the hook
scans the transcript for `<hypothesis-draft>`,
`<primitive-draft>`, `<chain-candidate>`, `<next-actions>` tags in
the *trusted assistant region* and persists them to the KG. Phase 0
fixed the injection vulnerability where attacker-controlled tool
responses could plant fake drafts.

**Primitive** — an attacker *capability* derived from a confirmed
finding (e.g. "arbitrary file read in tenant scope"). Has
prerequisites and effects; composed into chains.

**Protocol (KGProtocol)** — Phase 3 structural type that
documents the KG surface every consumer uses. Implemented by both
`KG` and `MockKG`.

**Recon** — the first agent in every scan. Walks the repo(s) and
produces the application model. Cheap (Sonnet); always runs in both
SAST and DAST kinds.

**Refute-pending** — the default adversary verdict, meaning the
adversary has not yet adjudicated the finding. The Stop hook refuses
to finish while any finding sits at `refute_pending`.

**SARIF** — Static Analysis Results Interchange Format 2.1.0.
Lacuna emits `findings.sarif` with Lacuna-specific properties
including `lacuna_adversary_verdict`, `lacuna_scan_kind`, and
`lacuna_evidence_paths`.

**SAST (Static Application Security Testing)** — analysis that reads
the source code without executing it. In Lacuna, the
`lacuna-recon` MCP server provides the toolbelt.

**Scope (scan_scope)** — `full` or `diff`. Distinct from *kind*.
Diff scope restricts hunters to the changed files and their
transitive imports.

**Skeptic** — the v3 adversary agent. Default verdict was
`confirmed`. Phase 2 replaced it with the *Adversary* whose default
is `refute_pending`. The skeptic agent file is retained for
backward compatibility but new scans should use the adversary.

**Trust shadow** — region of the application that lies within a
nominally trusted boundary but is reachable by untrusted input via
some path the trust model didn't anticipate. Mapped by the
*Trust Shadow Analyzer*.

**Two-adversary mode** — running *Adversary* and *Adversary-B* in
parallel on the same finding. Disagreement promotes the finding to
`needs_human` regardless of which adversary was "right." Enabled by
default in `scan_kind=sast_dast`.

**Validator** — the agent that adjudicates a hypothesis via the
red/blue dialectic skill. Promotes to *finding* (with evidence) or
refutes (with reasoning).

**Variant cluster** — a finding plus every hypothesis the
*Variant Hunter* derived from it. Surfaced in the technical report.

**Weird composition** — observations the *Chain Builder* found that
don't compose into a clean chain but are nonetheless interesting —
e.g. "primitive X plus primitive Y plus a particular config make a
fourth, unnamed capability." Surfaced in the technical report.
