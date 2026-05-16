# Lacuna — Architecture

> Agentic, multi-repo, application-level security scanner. Mythos-style behavior on Claude Code. SAST by default, DAST when configured. Runs as a Docker container — Bitbucket Cloud pipe or ad‑hoc.

---

## 1. Design goals (and the assumptions behind them)

| Goal | What it actually means in the architecture |
|---|---|
| **Application-level, not repo-level** | A "scan target" is an *application manifest* — a YAML declaring 1..N repos, their roles, and the boundaries between them. Lacuna mounts all of them into one workspace and reasons across them. |
| **Mythos-style agentic loop** | Hypothesis → test → validate/refute → record primitive → look for chains. The Stop hook forces continuation until exit criteria are met, not until the model runs out of things to say. |
| **Exploit chaining as a first-class concept** | Every finding contributes *primitives* to a knowledge graph. A dedicated chain-builder subagent continuously searches for sequences of primitives that compose into higher-severity outcomes. |
| **Semantic over syntactic** | Pattern-matching is delegated to deterministic tools (tree-sitter / semgrep-class queries). The LLM reasons over *shapes of risk*, not regex matches. |
| **Server-side compaction + context editing** | Use `PreCompact` hook to flush evidence to the KG before compaction. Use subagents aggressively so verbose tool output never reaches the main context. KG is the durable memory; transcript is scratch. |
| **Caveman-mode reasoning, no token budget** | Caveman skill loaded (direct, decisive, no hedging) — but explicitly told "token budget unlimited; exhaustive over terse for analysis." |
| **Multi-mode: SAST / SAST+DAST** | DAST tools are a separate MCP server that's only loaded when `--mode=sast+dast` is set. Hooks gate dangerous tool calls. |
| **Bitbucket Cloud first** | Native Bitbucket Pipe wrapper, but the same image runs ad-hoc with `docker run`. |
| **Azure Foundry, Opus + auto routing** | Claude Code points at Foundry's Anthropic-compatible endpoint. Subagents declare model preference; orchestrator + chain-builder + validator on Opus, recon and grep-class on Sonnet, label/triage on Haiku. |
| **Two outputs** | Executive report (business-language, attack scenarios, prioritized remediation) + Technical report (every finding, evidence, traces, PoCs, patches). |

---

## 2. High-level architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  HARNESS  (Docker container)                                             │
│                                                                          │
│  bitbucket-pipe wrapper  │  ad-hoc CLI  │  webhook receiver              │
│        └──────────┬──────────────┴───────────────┘                       │
│                   ▼                                                      │
│   ┌───────────────────────────────────────────────────────────────┐      │
│   │  ORCHESTRATOR  (main Claude Code agent, model: opus)          │      │
│   │  Reads manifest, plans phases, spawns subagents, owns report  │      │
│   └───────┬─────────────┬───────────────┬──────────────┬──────────┘      │
│           ▼             ▼               ▼              ▼                 │
│      ┌────────┐    ┌─────────┐   ┌──────────┐   ┌────────────┐           │
│      │ Recon  │    │ Vuln    │   │ Chain    │   │ Validator  │           │
│      │ agent  │    │ hunters │   │ builder  │   │ (red/blue) │           │
│      │ (×1)   │    │ (×N par)│   │ (×1)     │   │ (per find) │           │
│      └────┬───┘    └────┬────┘   └────┬─────┘   └─────┬──────┘           │
│           │             │             │               │                  │
│           ▼             ▼             ▼               ▼                  │
│   ┌───────────────────────────────────────────────────────────────┐      │
│   │              KNOWLEDGE GRAPH  (SQLite, durable)               │      │
│   │  findings • primitives • hypotheses • evidence • chains       │      │
│   └───────────────────────────────────────────────────────────────┘      │
│           ▲             ▲             ▲               ▲                  │
│           │             │             │               │                  │
│   ┌───────┴─────────────┴─────────────┴───────────────┴──────────┐       │
│   │           MCP TOOL SERVERS  (deterministic)                  │       │
│   │   lacuna-recon  •  lacuna-kg  •  lacuna-dast (gated)         │       │
│   └──────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  /workspace/{repo1,repo2,...}     /reports/      /state/scan-{id}.db     │
└──────────────────────────────────────────────────────────────────────────┘
```

Three things to internalize about this picture:

1. **The KG is the brain, not the transcript.** Agents come and go. Their context windows get compacted, edited, evicted. The KG is what persists. Every meaningful claim gets written there before the agent that produced it stops.
2. **Tools are deterministic; agents are speculative.** The MCP servers don't reason — they return facts. Agents form hypotheses about what those facts mean and what to look at next.
3. **The Stop hook is the loop.** Claude Code's main agent normally stops when it decides it's done. Lacuna's Stop hook checks exit criteria against the KG and, if unmet, blocks the stop and injects a continuation directive. This is how you get Mythos-style "keep going until you find something or have proven you can't."

---

## 3. Scan flow (and how the orchestrator drives it)

### Recon (deterministic, parallel-safe)
The orchestrator spawns the `recon` subagent with the manifest. Recon's only job is to call deterministic tools and write a *Repo Map* and *Service Map* into the KG.

Outputs into KG:
- `repo:*` — language, framework, LOC, entrypoint count
- `endpoint:*` — every HTTP route / queue consumer / CLI / lambda
- `auth:*` — auth middleware, login routes, session/JWT/OAuth flows
- `sink:*` — every dangerous sink with file:line
- `source:*` — every untrusted input source
- `cross_repo_call:*` — service A calls service B at endpoint X
- `dep:*` — every dependency + known CVEs
- `secret:*` — gitleaks/trufflehog hits
- `iac:*` — Terraform / k8s / Dockerfile configs of concern
- `hotspot:*` — git churn / recently changed / low test coverage
- `framework_caps:*` — for each framework, the well-known footguns

Recon writes a one-page **Application Model** summary into the KG as its handoff to the next stage. The main orchestrator only ever reads the summary — never the raw tool output.

### Hypothesize (semantic, parallel)
Orchestrator reads the Application Model and spawns specialized **Vuln Hunter** subagents in parallel. Each is opinionated about a *shape of risk*, not a CWE. Example shapes:

- **Trust-boundary smuggling** — input from source A reaches sink B without crossing a validated boundary
- **Cross-service auth confusion** — service B trusts a header from service A that A doesn't actually authenticate
- **Authorization drift** — endpoints that check authentication but not authorization, where the resource is user-scoped
- **Race / TOCTOU** — check-then-act patterns on filesystem, DB, cache
- **Deserialization & template injection** — sinks that consume user-controlled structured data
- **Memory corruption** (C/C++/Rust unsafe) — bounds, lifetime, unchecked offsets
- **Crypto misuse** — ECB, IV reuse, weak hashing for auth, JWT alg confusion
- **Business logic** — fed the API surface + DB schema, asked "what invariants does this app pretend to enforce, and where could they be violated?"

Each hunter writes **hypotheses** to the KG — explicit claims like *"endpoint POST /transfer in service `wallet` does not verify the source account belongs to the caller; provable by tracing param `from_account` through `controllers/wallet.py:144`."*

Crucially: hypotheses are not findings. They're claims awaiting validation.

### Validate (iterative, per-hypothesis)
For each hypothesis above some confidence threshold, the orchestrator spawns a **Validator** subagent with a tight remit: confirm or refute *this one claim*.

The validator runs a **red/blue dialectic** in a single context:
- *Red:* construct the most plausible exploit. SAST mode → trace the taint, draft a PoC payload or curl line. DAST mode → actually run it.
- *Blue:* steelman the defense. Find the missing sanitizer, the implicit type coercion, the framework's hidden escape, the WAF rule.
- Reconcile. If Red wins → promote hypothesis to **finding** with `confidence=high`, write evidence. If Blue wins → mark hypothesis `refuted` with reasoning (this matters — it prevents the same false lead from being re-explored). If neither wins → `confidence=medium, needs_human_review`.

This loop is *bounded by rounds*, not tokens. Default: up to 4 rounds per hypothesis. The validator's job is to be honest about uncertainty.

### Chain & Report
Every confirmed finding contributes one or more **primitives** to the KG. A primitive is an exploitable capability described in adversary terms:

> *"In `wallet` service, an authenticated user can cause arbitrary HTTP requests to be issued from the service's network position (SSRF via `webhook_url`). Requirement: any authenticated session. Yields: requests originate from inside the VPC."*

The **Chain Builder** subagent runs continuously alongside validation. Every time a primitive is added, it queries the KG: *do any new chains become possible?* It composes primitives by matching one primitive's *output* (capability gained) against another's *requirement*.

Example chain across two repos:
1. **SSRF** in `wallet` (low severity alone) →
2. **Internal admin API in `billing` trusts requests from inside VPC without auth** (medium alone) →
3. **Admin API can issue refunds without limit** →
4. **Chain → unbounded financial loss, critical.**

Each chain is itself an entity in the KG with its constituent primitives, prerequisites, and an adversary-style narrative.

Finally, the orchestrator invokes the `report-exec` and `report-tech` skills (see §8) to produce the two output documents from the KG.

---

## 4. Application manifest

```yaml
# app.lacuna.yaml
application:
  name: tenant-wallet-platform
  classification: pci-dss
  description: Customer-facing wallet + back-office billing
repos:
  - name: wallet-api
    source: bitbucket:acme/wallet-api
    ref: main
    role: backend-service
    runtime: python:3.12 / fastapi
    exposes: [https-public]
  - name: billing-svc
    source: bitbucket:acme/billing-svc
    ref: main
    role: backend-service
    runtime: go:1.22
    exposes: [grpc-internal]
  - name: wallet-web
    source: bitbucket:acme/wallet-web
    ref: main
    role: frontend
    runtime: node:20 / next.js
  - name: shared-protos
    source: bitbucket:acme/shared-protos
    ref: main
    role: shared-lib
trust_boundaries:
  - from: wallet-web
    to: wallet-api
    transport: https
    authn: jwt
  - from: wallet-api
    to: billing-svc
    transport: grpc
    authn: mtls
scan:
  mode: sast            # or sast+dast
  depth: thorough       # quick | standard | thorough | exhaustive
  exit_criteria:
    - all_hypotheses_resolved
    - chain_search_exhausted
  dast:                 # only used in sast+dast mode
    target: https://wallet.staging.internal
    auth:
      type: oauth_password_grant
      token_url: https://auth.staging/oauth/token
      credentials_env: LACUNA_DAST_CREDS
    safety:
      oob_listener: lacuna-oob.staging.internal
      rate_limit_rps: 10
      destructive_methods: deny   # PUT/PATCH/DELETE blocked by default
```

This manifest is the single input to the scanner. Bitbucket Cloud credentials/SSH come via env vars in the pipe.

---

## 5. Directory layout (the actual repo you'll be building)

```text
lacuna/
├── Dockerfile
├── README.md
├── pyproject.toml
├── bitbucket-pipe/
│   ├── pipe.yml
│   ├── pipe.sh
│   └── README.md
├── src/lacuna/
│   ├── __main__.py                # CLI: lacuna scan --manifest app.yaml
│   ├── harness/                   # Workspace setup, repo cloning, Claude Code invocation
│   │   └── workspace.py
│   ├── flow/                      # Inter-procedural taint engine
│   ├── precision/                 # Precision static analysis (integer/lifetime/format/type)
│   ├── dynamic/                   # Sanitizer build, libFuzzer, angr, differential parsers
│   ├── patches/                   # Patch-essence extraction + variant propagation
│   ├── oracles/                   # sqlmap / ysoserial / gopherus wrappers
│   ├── dast/                      # Playwright runner, OOB client, payload sets
│   ├── kg/
│   │   ├── schema.sql
│   │   ├── client.py
│   │   └── memory_adapter.py
│   ├── tools/                     # MCP servers + supporting tools
│   │   ├── recon_server.py
│   │   ├── kg_server.py
│   │   └── dast_server.py         # Loaded only in DAST mode
│   ├── hooks/
│   │   ├── pre_tool_use_gate.py
│   │   ├── post_tool_use_record.py
│   │   ├── pre_compact_flush.py
│   │   ├── stop_continuation.py
│   │   ├── subagent_stop_validate.py
│   │   ├── user_prompt_submit_inject_status.py
│   │   └── session_start.py
│   └── reports/
│       ├── generator.py
│       ├── sarif_emitter.py
│       ├── exec_template.md
│       └── tech_template.md
├── .claude/                       # Mounted into the running Claude Code session
│   ├── CLAUDE.md                  # Orchestrator system context
│   ├── settings.json              # Hook configuration
│   ├── agents/
│   │   ├── recon.md
│   │   ├── hunter-injection.md
│   │   ├── hunter-authn-authz.md
│   │   ├── hunter-race-toctou.md
│   │   ├── hunter-deserialization.md
│   │   ├── hunter-memory.md
│   │   ├── hunter-crypto.md
│   │   ├── hunter-business-logic.md
│   │   ├── hunter-cross-service.md
│   │   ├── validator.md
│   │   └── chain-builder.md
│   ├── skills/                # See .claude/skills/ for the live set
│   └── commands/
│       ├── kickoff.md
│       ├── status.md
│       └── force-chain-search.md
└── examples/
    ├── app.lacuna.yaml
    └── bitbucket-pipelines.yml
```

The `.claude/` directory is what makes this Lacuna and not just generic Claude Code. The container `COPY`s it into the working directory on startup; the harness then runs `claude` against it.

---

## 6. The orchestrator — `CLAUDE.md`

```markdown
# Lacuna Orchestrator

You are the orchestrator for Lacuna, an agentic application-security scanner.
You are NOT a chatbot. You are a long-running autonomous agent.

## Operating principles
1. The **Knowledge Graph (KG)** is your durable memory. Your context window is
   scratch. Write everything important to the KG immediately. Trust the KG
   over your own recollection.
2. **Hypotheses are not findings.** A hypothesis becomes a finding only after
   a Validator subagent confirms it via the red/blue dialectic.
3. **Spawn subagents aggressively.** Anything that requires reading more than
   ~500 lines of code, running a tool with verbose output, or exploring a
   tangent → goes to a subagent. Your context stays clean.
4. **Token budget is unlimited.** Do not abbreviate analysis, do not skip
   checks, do not "summarize for brevity." Exhaustive > terse when reasoning.
   Caveman skill governs *style* (direct, no hedging) not *depth*.
5. **You may not stop** until the KG reports `exit_criteria_met = true`. The
   Stop hook will reject your termination otherwise.

## Sequencing
1. Spawn `recon`. Wait for `application_model_ready` in KG.
2. Read the Application Model. For each shape-of-risk that applies to
   this application, spawn the matching `hunter-*` subagent in parallel.
3. As hypotheses appear in KG, spawn `validator` per hypothesis above
   confidence 0.3. The `chain-builder` subagent runs continuously from
   the moment the first finding is recorded.
4. When `all_hypotheses_resolved` and `chain_search_exhausted` are true,
   invoke skills `report-exec` and `report-tech`. Then stop.

## Tooling rules
- Use `lacuna-recon` for any structural question about a repo.
- Use `lacuna-kg` to read/write findings, hypotheses, primitives, chains.
- Never read a file directly when a recon tool can answer the question.
- DAST tools (`lacuna-dast.*`) are only available in sast+dast mode and are
  guarded by the PreToolUse hook. Do not attempt destructive verbs.

## When in doubt
Spawn a subagent. Ask the KG. Write down what you think and why. Then test it.
```

---

## 7. Subagent catalog

Subagents live in `.claude/agents/*.md` with YAML frontmatter. Every one of them shares two things: a model preference and a tools list.

**Auto model selection** — set via the `model:` frontmatter field per agent (each agent's `.md` file is the source of truth; do not duplicate the assignment here). Claude Code will route to the model declared. Through Azure Foundry, this maps to the corresponding Foundry deployment.

| Agent | Why | Key tools |
|---|---|---|
| `recon` | Tool-heavy, low reasoning depth, big I/O | `lacuna-recon.*`, `lacuna-kg.write` |
| `hunter-injection` | Trace data flow across files | `lacuna-recon.taint_paths`, `lacuna-recon.code_excerpt`, `lacuna-kg.*` |
| `hunter-authn-authz` | Deep cross-service reasoning | `lacuna-recon.auth_surface`, `.authz_checks`, `.endpoints`, KG |
| `hunter-race-toctou` | Subtle concurrency reasoning | `lacuna-recon.ast_query`, KG |
| `hunter-deserialization` | High-stakes, low false-positive tolerance | full recon + KG |
| `hunter-memory` | Only spawned for C/C++/Rust-unsafe code | full recon + KG |
| `hunter-crypto` | Mostly pattern-matching against known misuse | `crypto_usage`, KG |
| `hunter-business-logic` | Hardest — needs to infer invariants | recon + DB schema + API surface + KG |
| `hunter-cross-service` | Reasons across repo boundaries | `service_map`, `cross_repo_calls`, KG |
| `validator` | Red/blue dialectic, must be honest about uncertainty | full toolset, including DAST if enabled |
| `chain-builder` | Combinatorial reasoning over primitives | KG only — no code access needed |
| `triage-classifier` | Bulk severity tagging | KG read only |

Example agent file (`hunter-cross-service.md`):

```markdown
---
name: hunter-cross-service
description: Hunt for vulnerabilities that arise from how services trust each other across repos in this application. Use proactively when service_map shows >1 service with cross_repo_calls.
model: opus
tools: lacuna-recon.*, lacuna-kg.read, lacuna-kg.add_hypothesis
skills: semantic-pattern-matching, caveman
---

You are looking for cross-service trust failures in a multi-repo application.

## Shapes of risk you specialize in
- Service B accepts a header from service A that A doesn't authenticate
- Internal APIs reachable from the public network due to misconfigured mesh
- Implicit trust based on network position (VPC-only) that an SSRF anywhere
  in the app can bypass
- Differential parsing between services (one parses lenient, the other strict)
- Authentication context loss across hops (user A's request is processed as
  service A's identity downstream)

## Method
1. Read `service_map` and `cross_repo_calls` from KG.
2. For each edge in the service map, ask: what does the receiver trust about
   the sender, and how is that trust established? Look at the actual code on
   both sides — not the diagram.
3. For each trust assumption, look for a primitive elsewhere in the app that
   would let an attacker forge it.
4. Write hypotheses with explicit attacker scenarios.

## Style
Caveman skill is loaded: direct, decisive, no hedging in reasoning. But
token budget is unlimited — be exhaustive in your analysis.
```

---

## 8. Skill catalog

Skills are auto-loaded in-context instructions. They run in *whatever* agent invokes them. Key Lacuna skills:

### `caveman`
The standard caveman skill (direct, terse, decisive prose) **with an explicit override**:

```markdown
---
name: caveman
description: Direct caveman-style communication. Token budget is unlimited; depth of analysis must not be sacrificed for brevity.
---

# Style
- Direct. Decisive. No hedging. No "it might be worth considering."
- Short sentences in *prose*. No filler.

# Depth (overrides default caveman)
- Token budget is UNLIMITED for analysis.
- Do not skip analytical steps to save tokens.
- Do not summarize evidence away — write it down fully in the KG.
- "Brevity" applies to communication style, not investigation depth.

# In practice
- Reasoning chains: complete, every step articulated.
- KG writes: complete, every field populated.
- Prose to humans: terse, declarative, no padding.
```

### `semantic-pattern-matching`
Teaches agents to reason about *shapes of bugs* (e.g. "anything where untrusted bytes hit a structured-data parser without prior schema validation") rather than CWE IDs or regex patterns. Includes a library of vulnerability schemas in adversary terms.

### `red-blue-dialectic`
Used by the validator. Forces the agent to argue both sides of a hypothesis before concluding. Provides scaffolding for the back-and-forth and the reconciliation step.

### `primitive-extraction`
Used by the validator after a finding is confirmed. Given a confirmed bug, what *capability* does it grant an attacker? Writes a structured primitive into the KG with `prerequisites`, `effects`, `repos_involved`, `network_position_required`.

### `chain-construction`
Used by the chain-builder. Given the KG's primitive set, search for sequences whose composition reaches high-impact effects (RCE, data exfil, financial loss, privilege escalation, full account takeover, etc.).

### `poc-drafting`
For each confirmed finding, draft either a code-level trace (SAST) or a runnable PoC (DAST). Strict format so it lands cleanly in the technical report.

### `report-exec`
Generates the executive report from the KG. Audience: CISO, engineering leadership, product. Structure: risk summary, attack scenarios in business terms (each chain as a narrative), prioritized remediation roadmap, residual risk acknowledgment. Quantitative where useful, never gratuitous CVSS dumps.

### `report-tech`
Generates the technical report. Audience: engineers fixing the bugs. Structure: per-finding cards (location, evidence, taint trace or PoC, suggested patch, references), per-chain narratives, full primitive ledger as appendix.

---

## 9. Hook catalog

Hooks are where the "agentic loop" is actually enforced. Configured in `.claude/settings.json`.

| Hook | Type | Job |
|---|---|---|
| `SessionStart` | command | Load the manifest, initialize KG, ensure workspace is mounted, write `scan_started` marker. |
| `UserPromptSubmit` | command | (Used for ad-hoc mode where the user re-engages.) Inject current KG status summary so the orchestrator re-orients. |
| `PreToolUse` | command | **Gate destructive tools.** In SAST-only mode, block any `lacuna-dast.*` tool call. In SAST+DAST mode, block destructive HTTP verbs unless explicitly allow-listed in the manifest. Log every tool call for audit. |
| `PostToolUse` | command | **Auto-record evidence.** When `validator` confirms a finding, materialize the evidence (file excerpts, curl traces) to `/state/evidence/{finding_id}/`. Update KG. |
| `PreCompact` | command | **Flush context to KG before compaction.** Critical for Mythos-style memory. Extract any in-progress hypotheses, partial primitives, and decision rationales from the soon-to-be-compacted transcript and write them to KG. This is the equivalent of Mythos's server-side compaction. |
| `SubagentStop` | command | When a subagent stops, write its summary to KG. Verify it actually produced its expected output (e.g. recon must produce `application_model_ready`). Re-spawn if it stopped prematurely. |
| `Stop` | command | **The continuation loop.** Check `exit_criteria_met` in KG. If false, return `{"decision": "block", "reason": "<which criterion is failing>; continue from there."}` and the orchestrator keeps going. |
| `SessionEnd` | command | Finalize reports, sign + checksum the KG snapshot, exit with appropriate status code for the Bitbucket pipe (0 = no critical, 1 = critical/high findings present, 2 = scan error). |

Example `Stop` hook (`stop_continuation.py`):

```python
#!/usr/bin/env python3
"""Block Claude Code from stopping until exit criteria are met."""
import json, sys, sqlite3, os

db = sqlite3.connect(os.environ["LACUNA_KG_PATH"])
crit = dict(db.execute("SELECT name, met FROM exit_criteria").fetchall())

unmet = [name for name, met in crit.items() if not met]
if not unmet:
    sys.exit(0)  # allow stop

# Build continuation message
pending = db.execute(
    "SELECT id, summary FROM hypotheses WHERE status='pending' LIMIT 5"
).fetchall()
chains_to_explore = db.execute(
    "SELECT COUNT(*) FROM primitives WHERE chain_explored=0"
).fetchone()[0]

reason = (
    f"Exit criteria not met: {', '.join(unmet)}. "
    f"{len(pending)} hypotheses pending validation. "
    f"{chains_to_explore} primitives not yet considered for chain composition. "
    f"Continue."
)
print(json.dumps({"decision": "block", "reason": reason}))
sys.exit(0)
```

This single hook is what gives Lacuna its Mythos-like "won't stop until it's actually done" character.

---

## 10. Custom tools — the three MCP servers

These are the deterministic backbone. Agents call these instead of `grep` so they don't have to ingest raw output. Each MCP server is implemented as a Python process. The harness *generates* the workspace's `.mcp.json` at scan startup (see `harness/workspace.py`) so Claude Code picks up the recon/kg/dast servers with the right paths and credentials baked in; you should not edit `.mcp.json` directly — your changes will be overwritten on the next scan.

### `lacuna-recon` (always loaded)
The reconnaissance toolbelt — the answer to *"What tools should I give the orchestrator out the gate?"*

| Tool | Purpose |
|---|---|
| `app_inventory()` | Manifest + detected languages + LOC + frameworks per repo |
| `file_tree(repo, max_depth, include, exclude)` | Filtered tree |
| `language_stats(repo)` | Per-language LOC, file counts |
| `dependency_graph(repo)` | Parsed deps from package.json / requirements.txt / go.mod / pom.xml / Gemfile / Cargo.toml / etc. |
| `dependency_vulns(repo)` | OSV / trivy / npm-audit wrapper, returns CVEs with CVSS |
| `entrypoints(repo)` | All entrypoints: HTTP routes (Express/FastAPI/Spring/Rails/Gin/etc.), CLI commands, lambda handlers, queue consumers, cron jobs, event handlers |
| `api_surface(repo)` | OpenAPI / Swagger / GraphQL / gRPC proto / route definitions, normalized |
| `auth_surface(repo)` | Auth middleware, login routes, JWT/session/OAuth flows, token verification points |
| `authz_checks(repo)` | Authorization check sites (role checks, ownership checks, ACL lookups) |
| `data_sources(repo)` | All untrusted-input sources, classified |
| `data_sinks(repo)` | All dangerous sinks: exec, eval, SQL exec, HTTP clients, FS writes, template rendering, deserializers |
| `taint_paths(repo, source?, sink?)` | Source-to-sink paths via semgrep/codeql-class queries |
| `secret_scan(repo)` | gitleaks/trufflehog wrapper |
| `cross_repo_calls()` | HTTP/gRPC/queue calls *between* repos in the manifest |
| `service_map()` | Service DAG of the whole application |
| `db_schema(repo)` | Tables/columns from migrations (Rails/Django/Knex/Flyway/Alembic/Goose) |
| `iac_scan(repo)` | Terraform / CloudFormation / k8s / Dockerfile audit |
| `git_hotspots(repo)` | High-churn / recently-changed / large files |
| `git_blame(repo, file, line)` | Authorship for context |
| `framework_detect(repo)` | Frameworks + their well-known footguns |
| `crypto_usage(repo)` | All crypto API call sites |
| `serialize_calls(repo)` | Serialization/deserialization call sites |
| `template_engines(repo)` | Template rendering sites with user input |
| `regex_audit(repo)` | Potentially-catastrophic regexes (ReDoS) |
| `code_excerpt(repo, file, line, context_lines)` | Pull N lines around a location |
| `call_graph_at(repo, file, line)` | Callers + callees of a function |
| `ast_query(repo, language, query)` | Run an arbitrary tree-sitter query |
| `data_flow_trace(repo, file, line, variable)` | Trace a variable through code |

Implementation pragma: most of these wrap existing OSS tooling (semgrep, tree-sitter, trivy, gitleaks, osv-scanner, etc.). Lacuna's contribution is the unified, application-aware MCP surface — agents call one tool, not five.

### `lacuna-kg` (always loaded)
The knowledge graph CRUD surface. Keeps the agents from having to invent storage on their own.

| Tool | Purpose |
|---|---|
| `kg.read.findings(filters)` | Query findings |
| `kg.read.hypotheses(status?)` | Query hypotheses |
| `kg.read.primitives()` | List primitives |
| `kg.read.chains()` | List composed chains |
| `kg.read.application_model()` | The summary Recon produced |
| `kg.write.hypothesis(...)` | Record a hypothesis |
| `kg.write.finding(...)` | Promote hypothesis to finding (validator only) |
| `kg.write.refutation(...)` | Mark hypothesis refuted with reasoning |
| `kg.write.primitive(...)` | Record an exploit primitive |
| `kg.write.chain(...)` | Record a composed chain |
| `kg.write.evidence(finding_id, kind, payload)` | Attach evidence |
| `kg.status.exit_criteria()` | Read current state of exit criteria |

### `lacuna-dast` (loaded only in `sast+dast` mode, gated by PreToolUse)

| Tool | Purpose |
|---|---|
| `dast.http_request(method, url, headers, body)` | Send an HTTP request to the configured target. PreToolUse blocks destructive verbs unless allow-listed. |
| `dast.auth_login()` | Run the configured auth flow, return a session |
| `dast.endpoint_enum()` | Enumerate endpoints from OpenAPI + crawl |
| `dast.fuzz_param(endpoint, param, profile)` | Targeted fuzzing |
| `dast.oob_callback_listen(tag)` | Start an OOB listener, return URL for blind-detection payloads |
| `dast.oob_callback_poll(tag)` | Poll OOB listener for hits |
| `dast.crawl(start_url)` | Crawl from a start URL |

The DAST server has a **hard rate limit** and a **target allow-list** baked in at startup from the manifest, so a confused agent can't accidentally point Lacuna at production.

---

## 11. Knowledge graph schema (SQLite)

```sql
CREATE TABLE application_model (
  id INTEGER PRIMARY KEY,
  summary_md TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE hypotheses (
  id TEXT PRIMARY KEY,             -- ulid
  hunter TEXT NOT NULL,            -- subagent that produced it
  shape TEXT NOT NULL,             -- 'trust-boundary-smuggling', etc.
  repo TEXT,
  file TEXT,
  line INTEGER,
  description TEXT NOT NULL,
  attacker_scenario TEXT,
  confidence REAL NOT NULL,        -- 0..1, hunter's initial estimate
  status TEXT NOT NULL,            -- pending|validating|confirmed|refuted|needs_human
  refutation_reason TEXT,
  finding_id TEXT,                 -- set if promoted
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  hypothesis_id TEXT REFERENCES hypotheses(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,          -- low|medium|high|critical
  cvss_vector TEXT,
  cwes TEXT,                       -- comma-separated CWE ids
  repos_involved TEXT,             -- comma-separated
  validated_at TIMESTAMP,
  validator_summary TEXT NOT NULL
);

CREATE TABLE evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT REFERENCES findings(id),
  kind TEXT NOT NULL,              -- code_excerpt|taint_trace|http_trace|oob_hit|test_run
  payload_path TEXT NOT NULL,      -- relative to /state/evidence/
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE primitives (
  id TEXT PRIMARY KEY,
  finding_id TEXT REFERENCES findings(id),
  name TEXT NOT NULL,              -- 'ssrf-from-wallet-webhook'
  description TEXT NOT NULL,
  prerequisites TEXT NOT NULL,     -- JSON: required capabilities/network position
  effects TEXT NOT NULL,           -- JSON: capabilities gained
  repos_involved TEXT NOT NULL,
  chain_explored INTEGER DEFAULT 0
);

CREATE TABLE chains (
  id TEXT PRIMARY KEY,
  primitive_ids TEXT NOT NULL,     -- ordered, JSON array
  goal TEXT NOT NULL,              -- 'rce'|'data-exfil'|'financial-loss'|'priv-esc'|...
  combined_severity TEXT NOT NULL,
  narrative TEXT NOT NULL,         -- adversary-style story
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE exit_criteria (
  name TEXT PRIMARY KEY,
  met INTEGER NOT NULL DEFAULT 0,
  reason TEXT
);

CREATE TABLE tool_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  agent TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  result_summary TEXT
);
```

---

## 12. Context compaction & editing strategy (Mythos parity)

This is the hardest part to get right; spelling out exactly how each Mythos behavior maps:

| Mythos behavior | Lacuna mechanism |
|---|---|
| **Server-side compaction** | Claude Code's built-in compaction + Lacuna's `PreCompact` hook that flushes in-flight reasoning to the KG before context is summarized. After compaction the agent re-reads from the KG, not the lossy summary. |
| **Context editing (forgetting stale tool results)** | Aggressive subagent usage. The verbose output of `recon` never reaches the orchestrator's context — only the Application Model summary does. Same for every hunter. Subagent isolation *is* context editing. |
| **Long-running agent workflows without overload** | The Stop hook + KG durability mean a scan can run for hours across many compactions. Even if every transcript byte is summarized away, the KG carries forward everything that matters. |
| **Hypothesis-driven exploration** | The hypothesis-first design of the hunter stage. The agent never just "reads code looking for bugs" — it forms a claim, then tests it. |
| **Iterative test-retry-validate** | The validator's red/blue dialectic, bounded by *rounds* not tokens. The Stop hook continues the orchestrator until all hypotheses reach a terminal state. |
| **Semantic matching** | Hunters specialize by *shape of risk*, not CWE. The `semantic-pattern-matching` skill gives them the shapes. Tree-sitter / semgrep-class queries do the syntactic heavy lifting beneath. |
| **Exploit chaining** | Explicit first-class entity in the schema; `chain-builder` subagent runs continuously. |
| **Identify dormant bugs in old code** | `git_hotspots` deprioritizes recently-changed files; cross-service hunter looks at trust assumptions that have probably been there for years. The validator's red/blue prevents the "looks scary, is actually safe" bias. |

---

## 13. Azure Foundry + Claude Code wiring

Claude Code reads its provider config from environment variables. For Azure AI Foundry's Anthropic-compatible endpoint:

```bash
export ANTHROPIC_BASE_URL="https://<foundry-resource>.services.ai.azure.com/anthropic"
export ANTHROPIC_AUTH_TOKEN="<foundry-key-or-aad-bearer>"
export ANTHROPIC_MODEL="claude-opus-4-7"   # orchestrator default
export ANTHROPIC_SMALL_FAST_MODEL="claude-haiku-4-5"  # for cheap classification
```

Each subagent overrides via its frontmatter `model:` field. Foundry deployments are named to match the model strings the agents declare (`claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5`), so routing is automatic.

**Important:** verify the exact Foundry endpoint path and auth scheme against Azure's current docs (this changes more than Anthropic's own API does) and pin the SDK version in the Dockerfile.

---

## 14. Dockerfile (skeleton)

```dockerfile
FROM node:20-bookworm-slim AS base

# System deps for semgrep, tree-sitter, trivy, git
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl jq ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Semgrep
RUN pip3 install --no-cache-dir --break-system-packages semgrep osv-scanner gitleaks

# Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Lacuna itself
WORKDIR /opt/lacuna
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Claude Code config (agents, skills, hooks, MCP)
COPY .claude/ /root/.claude/
COPY .mcp.json /root/.mcp.json
COPY bitbucket-pipe/pipe.sh /opt/lacuna/pipe.sh
RUN chmod +x /opt/lacuna/pipe.sh

ENV LACUNA_KG_PATH=/state/lacuna.db
WORKDIR /workspace
ENTRYPOINT ["/opt/lacuna/pipe.sh"]
```

`pipe.sh` is the dual-mode entrypoint: it detects whether it's running inside a Bitbucket pipeline (via `$BITBUCKET_*` env) or ad-hoc, and adapts.

---

## 15. Bitbucket Cloud pipe

`bitbucket-pipe/pipe.yml`:
```yaml
name: Lacuna Security Scanner
image: acme/lacuna:3.1.1
description: Application-level agentic security scanner
variables:
  - name: LACUNA_MANIFEST
    default: app.lacuna.yaml
  - name: LACUNA_MODE
    default: sast
    allowed-values: [sast, sast+dast]
  - name: AZURE_FOUNDRY_ENDPOINT
  - name: AZURE_FOUNDRY_KEY
    secured: true
  - name: BITBUCKET_APP_PASSWORD
    secured: true
  - name: LACUNA_FAIL_ON
    default: critical
    allowed-values: [none, critical, high, medium]
```

Consumer's `bitbucket-pipelines.yml`:
```yaml
pipelines:
  custom:
    nightly-security-scan:
      - step:
          name: Lacuna application scan
          services: [docker]
          script:
            - pipe: docker://acme/lacuna:3.1.1
              variables:
                LACUNA_MANIFEST: 'app.lacuna.yaml'
                LACUNA_MODE: 'sast'
                AZURE_FOUNDRY_ENDPOINT: $AZURE_FOUNDRY_ENDPOINT
                AZURE_FOUNDRY_KEY: $AZURE_FOUNDRY_KEY
                BITBUCKET_APP_PASSWORD: $BITBUCKET_APP_PASSWORD
                LACUNA_FAIL_ON: 'critical'
          artifacts:
            - reports/**
```

`pipe.sh` responsibilities:
1. Read manifest (already in repo working dir or fetched from primary repo).
2. For each `repos[]` entry, `git clone` into `/workspace/<name>` using the Bitbucket App Password (or workspace token).
3. Initialize KG at `/state/lacuna.db`.
4. Start MCP servers (`lacuna-recon`, `lacuna-kg`, and `lacuna-dast` if DAST mode).
5. Invoke `claude --dangerously-skip-permissions -p "Begin scan"` (or with permissions if you want approval gates) against the loaded `.claude/` config.
6. After the orchestrator stops, copy `/state/reports/{executive,technical}.md` to `/workspace/reports/`.
7. Exit with the right code based on `LACUNA_FAIL_ON`.

---

## 16. Ad-hoc invocation

Same image, different entrypoint:

```bash
docker run --rm \
  -v $PWD/app.lacuna.yaml:/workspace/app.lacuna.yaml:ro \
  -v $PWD/reports:/workspace/reports \
  -v lacuna-state:/state \
  -e AZURE_FOUNDRY_ENDPOINT=... \
  -e AZURE_FOUNDRY_KEY=... \
  -e BITBUCKET_APP_PASSWORD=... \
  acme/lacuna:3.1.1 \
  scan --manifest /workspace/app.lacuna.yaml --mode sast
```

Resumable scans: `--resume <scan-id>` mounts the prior KG and continues. Combined with the Stop hook, this makes long scans interruption-tolerant.

---

## 17. Reports

Both reports are generated by skills (`report-exec`, `report-tech`) that read the KG. They are **not** generated by the orchestrator inline — that would risk lossy regeneration after compaction. They are the *materialization* of the KG into prose.

### Executive report — structure
1. **One-paragraph headline.** Highest-severity outcome the scanner found, in business language.
2. **Risk summary.** Counts by severity, comparison to prior scan (if KG history exists), 5–10 word descriptors of each critical chain.
3. **Attack scenarios.** One narrative per critical/high chain. Plain English. *"An attacker with a free user account could, in four steps, drain refund balances..."* No CWE IDs in this section.
4. **Top business impacts.** Mapped from chains: data exposure, financial loss, service disruption, regulatory exposure.
5. **Prioritized remediation roadmap.** Ranked by reduction-in-risk-per-engineer-hour, not by raw severity.
6. **Residual risk acknowledgment.** What the scan *couldn't* validate, and where human review is recommended.

### Technical report — structure
1. **Application model summary** (from Recon).
2. **Findings catalog**, one card per finding:
   - title, severity, CVSS, repos+files+lines
   - taint trace or PoC (from evidence)
   - patch suggestion (skill-generated, marked as suggestion not source of truth)
   - cross-references to chains this finding participates in
3. **Primitives ledger.** Every primitive recorded, with prerequisites and effects.
4. **Chain analyses.** Each chain with constituent primitives, step-by-step exploitation narrative, defense-in-depth options.
5. **Refuted hypotheses appendix.** What was checked and ruled out, with reasoning. This is what separates a real scanner from a noise generator — it shows the work.
6. **Tool audit log.** Every MCP call made during the scan, hashable for reproducibility.

---

## 18. The Mythos lessons baked in

Pulling out the four most important architectural choices that make this Mythos-shaped rather than Snyk-shaped:

1. **The KG is the agent, the LLM is the worker.** Mythos's "context compaction" is really "the long-term memory isn't the transcript." Same here: agents come and go, the KG persists. This single decision is what makes long-running, self-recovering, exploit-chaining scans possible.

2. **Hypotheses are the unit of work, not findings.** Mythos doesn't "scan and report" — it *poses and tests*. The hunter/validator stages mirror that: speculation is cheap, validation is rigorous, and refuted hypotheses are evidence of work done, not waste.

3. **Primitives + chains beat severities.** A SAST tool reports 200 mediums and one false-positive critical. Lacuna reports five primitives and the two chains that compose them into account takeover. The composition layer is the value.

4. **The Stop hook is the agent's spine.** Without it, the model decides when it's done — and models love to declare success. With it, the *system* decides, against criteria written in the KG. This is what makes Lacuna an autonomous scanner rather than a chat session that happens to scan.
