# Lacuna Changelog

## v3.0.0 — 2026-05-14

CVE-grade vulnerability discovery. v2 found credible application-level
bugs; v3 finds memory-safety bugs with crashing inputs, propagates fix
patterns to find variants, and reasons like a vulnerability researcher
rather than a pattern matcher.

### Layer 2 — Precision static analysis

Five new analyzers under `src/lacuna/precision/`. Each produces
`precision_findings` (high-quality leads) that hunters consume:

- **`integer_range`** — CWE-190/789. Detects allocations whose size
  expression derives from attacker-controlled values without bounds
  checks. Per-variable shape lattice (constant / attacker / derived /
  checked), with bound-check propagation through `if (n < MAX)` style
  guards. C/C++/Python/Java/Go.

- **`lifetime`** — CWE-416/415. Per-function alloc/free/use-after-free
  tracking with alias propagation. Covers malloc/calloc/realloc/kmalloc/
  strdup/new family. Detects double-free and use-after-free at the same
  granularity. C/C++/Obj-C.

- **`format_string`** — CWE-134/117. printf-family with non-literal
  format string, plus the Log4Shell-style logger-as-template pattern.
  Cross-references `dependency_graph` for log4j-core version to gate
  high-severity classification on the actually-vulnerable version range.

- **`type_confusion`** — CWE-843. Casts/coercions across trust boundaries
  without runtime guarantees. Per-language: Python pickle+attr access,
  Java deserialize+cast without instanceof, C++ reinterpret_cast on
  buffer pointers, Go panic-on-fail type assertions on JSON output,
  TypeScript `as T` after JSON.parse.

- **`allocator_map`** — meta tool. Identifies allocators in use:
  standard malloc/free, kernel kmalloc with GFP flags, custom `*_alloc/
  *_free` pairs, C++ smart pointers, refcount families. Metadata for
  the other tools — informs bug-class reasoning.

### Layer 3 — Dynamic confirmation oracles

Crashing inputs are the strongest possible evidence. New modules under
`src/lacuna/dynamic/`:

- **`sanitizer_build`** — auto-detect build system (cmake/autotools/
  make/cargo/meson), build with `-fsanitize=address,undefined`. Returns
  binaries, build status, and any UBSan warnings caught at compile time
  (which are themselves findings). Memoized in KG by `(repo, git_sha)`.

- **`fuzzer`** — libFuzzer harness wrapper. Generates a harness from
  function signature, builds against the sanitizer-instrumented library,
  runs for N seconds, parses ASan reports, minimizes crashes, classifies
  bug class from sanitizer output. Default 5 min per function;
  `LACUNA_FUZZ_BUDGET_MINUTES` caps the per-scan total.

- **`symex`** — angr symbolic execution. Find a concrete input that
  drives execution from source to target. Runs as subprocess for hard
  timeout enforcement. Used when fuzzing fails to hit a deep path.

- **`differential`** — multi-parser oracle. Same input, multiple parser
  implementations, report divergence. Built-in parser pairs reproduce
  the real-world quirks behind request smuggling (CL.TE, TE.CL, CL.CL),
  URL parser confusion (WHATWG vs RFC 3986 backslash handling), JSON
  duplicate-key resolution. Catches the parser-discrepancy CVE class
  that static analysis misses entirely.

### Layer 4 — Patch-diff and variant infrastructure

The Mythos-style observation: a fix tells you the bug class; most fixes
are site-level; variants survive. New modules under `src/lacuna/patches/`:

- **`patch_essence`** — given a git commit (or raw diff), extract the
  bug class abstractly, generate a semgrep-style propagation rule that
  matches the BEFORE shape. Identifies guard introductions (added
  isinstance/bound-check/escape) and dangerous removals (concat-into-SQL,
  eval, pickle.loads). Classifies CWE from the evidence intersection.

- **`propagate_pattern`** — runs a generated rule against the codebase
  to find sibling instances. Uses semgrep when available, falls back to
  regex-based matching when it isn't. The variant multiplier in real
  codebases is empirically 1.5-4×.

### Layer 5 — Researcher mindset, encoded as skills

Six new skills under `.claude/skills/`:

- **`vulnerability-researcher`** — the discipline that produces CVEs.
  "The function is not its name; trust gradient = bug gradient; default
  behavior is the bug." When to apply it, when to skip.

- **`interesting-input`** — per-type boundary sets for "what input would
  make this function behave maximally surprisingly?" Integers, strings,
  floats, arrays, network input, URLs, JSON, file uploads — concrete
  values per type.

- **`trust-the-fuzzer`** — when static analysis says safe and fuzzing
  crashes, fuzzing wins. Hard rule for the validator and the skeptic:
  a matching-CWE crash forbids the `refuted` verdict.

- **`read-the-fix`** — how to read a security commit. Four questions:
  what was the bug class, is the fix at the right abstraction level,
  was it complete, what did the author not notice?

- **`adversary-pricing`** — would a real attacker bother? Five-factor
  scoring (effort / reliability / value / stealth / reusability) that
  produces a severity tier, calibrating CVSS to economic reality.

### New agents

Three new agents under `.claude/agents/`:

- **`patch-archaeologist`** — Phase 2 specialist. Reads recent security
  commits, extracts patch essences, propagates rules across the codebase,
  files hypotheses for surviving variants at confidence 0.6. Cites the
  parent commit as evidence.

- **`variant-hunter`** — auto-spawned in Phase 3.6 whenever the validator
  confirms a finding. Generates a propagation rule from the bug pattern,
  finds sibling sites, files child hypotheses at confidence 0.65 linked
  via `variant_links` to the parent.

- **`fuzzing-coordinator`** — Phase 3.5 singleton. Decides what to fuzz
  based on precision findings + hypothesis confidence band (0.4-0.8),
  triggers sanitizer builds as needed, dispatches `fuzz_function`,
  attaches crash evidence to parent hypotheses. Operates under
  `LACUNA_FUZZ_BUDGET_MINUTES`.

### KG schema additions

Six new tables: `precision_findings`, `sanitizer_builds`, `fuzz_runs`,
`fuzz_crashes`, `patch_rules`, `variant_links`, `differential_findings`.
All client methods exposed via the `kg_server` MCP tools.

### Orchestration changes

`CLAUDE.md` Phase 1.5 (precision precondition pass), Phase 2b (patch
archaeology in parallel), Phase 3.5 (dynamic confirmation), Phase 3.6
(variant hunting per confirmed finding). New stop-hook gates: no
in-flight `fuzz_runs`, no unreviewed high-severity precision findings,
variant child hypotheses must all have verdicts.

### Reports

`tech_template.md` gains four new sections: Variant Clusters, Crash
Reproductions, Incomplete-Fix Findings, Precision Findings summary.
`generator.py` collects from the new KG tables.

### Dockerfile

Adds clang/libfuzzer-14-dev, llvm, cmake, autoconf, automake, libtool,
ninja-build, meson, gdb. New env: `LACUNA_FUZZ_BUDGET_MINUTES=60`,
`LACUNA_FUZZ_WORKSPACE=/state/fuzz`, `LACUNA_SANITIZER_BUILD_DIR=/state/
sanitizer-builds`, `LACUNA_SYMEX_TIMEOUT_S=60`, `CC=clang`, `CXX=clang++`.
`pyproject.toml` oracles extra adds `angr>=9.2.0`.

### Tests

`test_precision.py`, `test_differential.py`, `test_kg_v3.py`,
`test_patches.py`. 29 v3-specific tests covering precision tools,
parser-divergence oracle, KG roundtrips, and end-to-end patch
essence → variant propagation against a real git repo.

### Non-goals (explicit)

- 0-day discovery in mature C/C++ kernels/browsers/hypervisors is not
  on the table. v3 finds the CVEs that your dependencies already have,
  the variants of historical CVEs in your own copy-pasted code, and
  the easy memory bugs in less-mature C/C++.
- The external CVE corpus (NVD/OSV/GHSA mirror) is designed but not
  built in this release. The patch infrastructure works on internal
  git history; the CVE corpus would extend it to cross-reference
  third-party fixes.

---

## v2.0.0 — 2026-05-14

Massive depth upgrade. v1 shipped a working agentic SAST+DAST scanner.
v2 adds the things that take findings from "credible hypotheses" to "deep
chains a human researcher would have found." 21 separate enhancements,
grouped below.

### Tier 1 — Deeper finds

- **Git history as first-class tools.** New recon tools `git_blame_function`,
  `recent_security_commits`, `function_change_history`,
  `removed_code_in_last_n_days`, `commit_message_search`. Bugs cluster near
  recent security fixes; deletions are evidence too. (`tools/git_history.py`)

- **Inter-procedural data-flow engine.** A from-scratch CodeQL-equivalent
  taint analyzer: call-graph construction, def-use chains, source/sink/
  sanitizer pattern catalogs, inter-procedural propagation through function
  returns. Resolves f-string injection, sanitizer-suppressed flows, and
  recursive chains up to depth 6. Persists results to KG `flow_paths`.
  (`flow/ast_parse.py`, `flow/callgraph.py`, `flow/taint.py`)

- **Callgraph reachability oracle.** `reachable_from(source, target)` —
  refutes "is X reachable from any handler" hypotheses in milliseconds.
  Cached in KG. (`flow/callgraph.py:reachable_from`)

- **Cross-hunter shared observation board.** New KG table `observations`
  with kinds `middleware_bypass`, `sanitizer_bypass`, `framework_quirk`,
  `secret_location`, `trust_boundary_hole`, `shared_state`,
  `reachability_fact`, `library_gadget`. Every hunter reads at start,
  writes derived facts during hunt. New skill `cross-hunter-observations`.

- **Speculative re-open during validation.** When chain-builder produces a
  candidate whose prereq is "attacker has X," the orchestrator re-spawns
  relevant hunters with X as a starting state. Cap: 2 re-opens per chain
  candidate. (`CLAUDE.md` Phase 3c)

- **Adversarial validation pass.** New `skeptic` agent (Haiku) re-reviews
  every confirmed medium+ finding and emits verdicts (`confirmed` /
  `downgrade` / `refuted` / `needs_human`). Stop hook refuses termination
  until all medium+ findings are skeptic-reviewed.
  (`.claude/agents/skeptic.md`)

### Tier 2 — Broader reach

- **Known-gadget catalog.** 21 pre-seeded exploit chains across Java
  (CommonsCollections 1/6, CommonsBeanutils, SnakeYAML, Log4Shell,
  Spring4Shell), Python (pickle, yaml.load, Jinja2 SSTI, Werkzeug debug
  PIN, Celery), Node (lodash proto pollution, node-serialize, Handlebars
  SSTI), Ruby, PHP, .NET. Queried via `known_gadgets`.
  (`tools/gadget_catalog.py`)

- **Bug-class deep oracles.** Wrappers for sqlmap (SQLi confirmation),
  ysoserial (Java/.NET deserialization payloads), gopherus (gopher://
  SSRF). Invoked by validators when 4-round dialectic is inconclusive.
  (`oracles/`)

- **Headless browser DAST.** Playwright runner with three scenarios:
  DOM-XSS (5 payloads, console + alert hooks), postMessage abuse
  (4 payloads), DOM clobbering (named-element overrides of globals).
  (`dast/playwright_runner.py`)

- **State-machine extraction.** Builds an FSM from session writes,
  redirects, and route handlers. Flags transitions that write a stateful
  field without first reading its prior value — multi-step flow bypass
  candidates. (`tools/state_machine.py`)

- **Custom semgrep rules per scan.** Generates a ruleset tailored to the
  app's detected frameworks (Flask, Django, Express, etc.) and languages.
  Far fewer false positives than canned packs.
  (`tools/custom_semgrep.py`)

- **Test corpus as oracle.** `test_coverage_for_endpoint`,
  `test_assertions_for_function`, `untested_handlers`. Untested
  endpoints get extra hunter attention; functions whose tests assert the
  wrong thing get flagged. (`tools/test_coverage.py`)

### Parallelism

- **Per-phase parallelism.** New `subagents.perPhaseParallel` in settings:
  recon per-repo, hunters as `(shape × repo)` matrix, validators concurrent,
  DAST across distinct allowed_hosts, skeptic per-finding.
  (`.claude/settings.json`)

- **Incremental chain-builder.** Triggered every 5 new primitives instead
  of only at scan-end. Chains often emerge mid-scan; finding them early
  enables speculative re-open.

### Mythos-pattern

- **Weird-machine skill.** Catalog of unintended computations for SSRF,
  XSS, open redirect, cache headers, logging, path traversal, race
  conditions, info leak. Worked example: stored XSS + admin SSRF +
  gopher://redis → SSH key RCE. (`.claude/skills/weird-machine/SKILL.md`)

- **Trust-shadow mapping.** New `trust-shadow-analyzer` agent (Opus) +
  `tools/trust_shadow.py`. Builds the application's capability graph:
  for every secret/key/role, who can read, use, sign, authorize. KG
  tables `capabilities` + `capability_edges`. Surfaces cross-service
  trust paths that are vulns even when neither side is buggy alone.

- **Minimal repro enforcement.** New skill + KG table `minimal_repros`.
  Validator must call `kg.write.minimal_repro` after confirmation. Stop
  hook gates on `findings_lacking_minimal_repros`.
  (`.claude/skills/minimal-repro/SKILL.md`)

- **Coverage-aware reporting.** Tech report now has "Coverage Gaps (We Did
  Not Examine)", "Trust Shadow", "Weird Compositions", "Skeptic Reviews",
  "Cross-Hunter Observations" sections. (`reports/tech_template.md`,
  `reports/generator.py`)

### KG schema additions

```sql
observations          -- cross-hunter board
gadgets               -- pre-seeded exploit chains
capabilities          -- trust-shadow nodes
capability_edges      -- trust-shadow edges
weird_compositions    -- unintended-computation records
minimal_repros        -- per-finding minimized payload
coverage_gaps         -- negative-space findings
reachability_cache    -- callgraph reachability cache
flow_paths            -- persisted taint paths from the engine
```

All have CRUD methods on `KG`, all exposed as MCP tools in `kg_server.py`.

### New environment variables

- `YSOSERIAL_JAR` — path to ysoserial-all.jar (default `/opt/ysoserial-all.jar`)
- `YSOSERIAL_NET` — path to ysoserial.net (default `/opt/ysoserial.net/ysoserial.exe`)
- `GOPHERUS_BIN` — gopherus binary (default `gopherus`)

### New Docker dependencies

The image now ships sqlmap, playwright + chromium, ysoserial.jar, gopherus,
and JRE (for ysoserial), in addition to the v1 set (semgrep, trivy, gitleaks,
osv-scanner).

### Backwards compatibility

v1 manifests, KG paths, and reports continue to work. The new tables are
created idempotently; old scans loaded into a v2 binary will simply have
empty v2 sections. The `lacuna report` command auto-upgrades the schema.

### Verified

- Flow engine: 8 tests pass (`tests/test_flow_engine.py`).
- KG v2 extensions: smoke test passes (observations, capabilities,
  weird compositions, coverage gaps, flow paths, status_summary).
- Gadget catalog: 21 entries seed cleanly.
- All 40 Python modules syntax-clean; all 13 YAML + 1 JSON config files
  parse cleanly.

---

## v1.0.0 — 2026-05-14 (earlier in the day)

Initial release. Agentic SAST+DAST scanner for Bitbucket Cloud pipes via
Azure Foundry. Recon, 8 hunters, validator with red/blue dialectic,
chain-builder, ephemeral KG, Markdown + SARIF reports.
