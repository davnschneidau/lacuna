# Lacuna Changelog

## 3.0.0 — 2026-05-14

Initial public release. Lacuna is an agentic, multi-repo, application-level
security scanner that runs on top of Claude Code and ships as a Docker
container. The 3.0.0 release reflects the version the project went public
with; earlier iterations exist only in this repository's git history and
are not separately versioned.

### What ships in 3.0.0

**Static analysis.**

* Inter-procedural taint engine (`src/lacuna/flow/`) built on
  `tree-sitter-language-pack` for AST parsing — call-graph construction,
  def-use chains, source/sink/sanitizer catalogs, depth-limited
  inter-procedural propagation.
* Precision analyzers (`src/lacuna/precision/`):
  * `integer_range` (CWE-190/789) with bound-check propagation.
  * `lifetime` (CWE-416/415/824) with branch-aware pointer-state and
    alias tracking for C/C++/Obj-C.
  * `format_string` (CWE-134/117) including Log4Shell-style logger-as-
    template detection.
  * `type_confusion` (CWE-843) across Python pickle, Java casts after
    deserialize, C++ `reinterpret_cast` on buffers, Go panic-on-fail
    type assertions, TypeScript `as T` after JSON.parse.
  * `allocator_map` — metadata for the above.

**Dynamic confirmation.**

* `sanitizer_build` — auto-detect build system (CMake / Autotools /
  plain Make / Cargo / Meson), build with ASan + UBSan, memoize per
  `(repo, git_sha)`.
* `fuzzer` — libFuzzer harness wrapper. C-vs-C++ detection via the
  compiled library's symbol table; ASan replay and crash minimization.
* `symex` — angr subprocess driver with SIGALRM hard-stop and robust
  JSON parsing on stdout.
* `differential` — multi-parser oracle for HTTP request smuggling
  (CL.TE / TE.CL / CL.CL), URL parser confusion (approximated WHATWG
  vs RFC 3986), and JSON duplicate-key resolution.

**Patch infrastructure.**

* `patch_essence` extracts the bug-class abstraction from a fix commit
  (`git show <sha>`), classifies the CWE from guard-add / sink-remove
  evidence, and emits a semgrep rule.
* `propagate_pattern` runs the generated rule across the codebase via
  semgrep (when available) or a DOTALL|MULTILINE regex fallback with
  cached file reads.

**Agent topology.**

* Orchestrator (`CLAUDE.md`) plus subagents: `recon`, eight hunters
  (`injection`, `authn-authz`, `crypto`, `deserialization`,
  `business-logic`, `cross-service`, `memory`, `race-toctou`),
  `validator`, `chain-builder`, `skeptic`, `trust-shadow-analyzer`,
  `patch-archaeologist`, `variant-hunter`, `fuzzing-coordinator`,
  `triage-classifier`.
* Skills under `.claude/skills/` for the researcher mindset
  (`vulnerability-researcher`, `interesting-input`, `trust-the-fuzzer`,
  `read-the-fix`, `adversary-pricing`, `minimal-repro`,
  `red-blue-dialectic`, `chain-construction`, `primitive-extraction`,
  `poc-drafting`, `report-exec`, `report-tech`, `weird-machine`,
  `trust-shadow-mapping`, `cross-hunter-observations`,
  `semantic-pattern-matching`, `dast-orchestration`, `caveman`).

**Knowledge graph.**

* Ephemeral per-scan SQLite database under `src/lacuna/kg/`. Tables
  cover findings, hypotheses, primitives, chains, evidence,
  observations, capabilities, weird compositions, minimal repros,
  coverage gaps, precision findings, sanitizer builds, fuzz runs and
  crashes, patch rules, variant links, differential findings, the
  cross-hunter board, dependencies, and an audit event log.
* Hook-rate-limit ledger (`hook_tool_calls`) replaces the previous
  process-local counter so PreToolUse caps survive Claude Code's
  per-tool subprocess fan-out.

**DAST.**

* Three MCP tool suites: `lacuna-recon`, `lacuna-kg`, `lacuna-dast`.
* Playwright runner for DOM-XSS, postMessage abuse, and DOM clobbering.
* Raw-socket HTTP smuggling probe (bypasses `httpx`'s header
  normalization).
* OOB callback collector client with an explicit `OobNotConfigured`
  exception when no collector URL is configured.

**Hardening relative to the pre-release working tree.**

* `git clone` no longer embeds credentials in the URL — uses a
  per-scan `GIT_ASKPASS` shim. `BITBUCKET_ACCESS_TOKEN` is supported
  alongside username + app password.
* Child-process environment is whitelisted (`LACUNA_*`, `ANTHROPIC_*`,
  `CLAUDE_*`, `PATH`, `HOME`, `LANG`, `LC_*`) — no accidental
  leakage of `AWS_*`, `GITHUB_*`, etc.
* `LACUNA_WALL_CLOCK_HOURS` enforced via `subprocess.run(timeout=...)`.
* `LACUNA_BUDGET_USD` enforced post-run against the KG's
  `token_cost_usd` total.
* Maven `pom.xml` parser uses `defusedxml`.
* Tool-name sanitization on cached payload paths prevents traversal.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LACUNA_MODE` | `sast` | `sast` or `sast+dast` |
| `LACUNA_MANIFEST` | `app.lacuna.yaml` | Manifest path |
| `LACUNA_FAIL_ON` | `critical` | Gate severity |
| `LACUNA_MODEL_OPUS` | `claude-opus-4-7` | Foundry deployment |
| `LACUNA_MODEL_SONNET` | `claude-sonnet-4-5` | Foundry deployment |
| `LACUNA_MODEL_HAIKU` | `claude-haiku-4-5` | Foundry deployment |
| `LACUNA_WALL_CLOCK_HOURS` | `4` | Hard cap per scan |
| `LACUNA_BUDGET_USD` | unset | Soft USD cap |
| `LACUNA_MAX_PARALLEL_SUBAGENTS` | `8` | Concurrency |
| `LACUNA_FUZZ_BUDGET_MINUTES` | `60` | Total fuzz budget per scan |
| `LACUNA_CLONE_DEPTH` | `0` | `0` = full clone; non-zero = `--depth N` |
| `LACUNA_BUILD_PARALLELISM` | min(nproc, 4) | `make -j` cap |
| `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD` *or* `BITBUCKET_ACCESS_TOKEN` | — | Repo clone credentials |

### Known limitations

* The WHATWG URL parser in `differential.py` is an approximation, not a
  spec-conformant implementation. It is tuned to surface the
  divergences that drive parser-confusion CVEs.
* The dollar-budget cap (`LACUNA_BUDGET_USD`) is enforced via the
  agent's own `token_cost_usd` accounting, not via the Anthropic
  billing API. Treat as a soft cap.
* External CVE corpus integration (NVD/OSV/GHSA mirror) is designed
  but not built. The patch infrastructure works on internal git
  history; the corpus would extend it to cross-reference third-party
  fixes.
* libFuzzer / angr / ysoserial / sqlmap / Playwright are best-effort
  wrappers around external tooling and fail loudly when their
  dependencies are missing.
