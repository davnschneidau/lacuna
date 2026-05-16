# Lacuna

> Agentic, multi-repo, application-level security scanner. Mythos-style behavior on top of Claude Code. SAST and DAST in one box. Runs as a Docker container — Bitbucket Cloud pipe or ad-hoc.

**3.1.1** — version reconciliation across pyproject, pipe, image tags, docs. No behavior change vs 3.1.0; see CHANGELOG. The single source of truth for the version is `src/lacuna/__init__.py:__version__`; everything else reads it.

**3.1.0** — cost-optimized specialist agents + risk timeline. New in this release:

- **Multi-model tiering** reduces cost 3-4× with negligible quality loss:
  - Opus for orchestrator, trust-shadow-analyzer, chain-builder, validator, and deep reasoning hunters
  - Sonnet for recon, pattern-matching hunters, and low-confidence validation
  - Haiku for skeptic and triage
  - Target spend: ~15% Haiku + 45% Sonnet + 40% Opus
- **PR-scoped diff mode** (`LACUNA_MODE=diff`) scans only changed files and their transitive imports
- **Tool-call result caching** provides 5-10× speedup on repeated scans
- **JWT forensics oracle** with 6 attack vectors (alg=none, confusion, kid injection, JWKS SSRF, brute-force)
- **Specialist hunters**: OAuth/OIDC, mass-assignment, SSRF (3-tier), GraphQL, CI/CD supply-chain
- **Risk-timeline mode** tracks findings across scans with delta analysis (new/fixed/persisted/regressed)
- **CVE mapper** cross-references dependencies against curated corpus (npm/pypi/maven/go)
- **Skills**: threat modeling, variant hunting, counterfactual reasoning, patch suggestion, test generation

**3.0.0** — initial public release. Bundles:

* the inter-procedural taint / data-flow engine,
* precision static analysis (integer overflow, use-after-free, format
  strings, type confusion),
* dynamic confirmation oracles (sanitizer builds, libFuzzer, angr
  symex, parser-differential testing),
* patch-essence extraction and variant propagation,
* deep oracles (sqlmap / ysoserial / gopherus),
* a headless Playwright DAST runner,
* the skeptic + trust-shadow + patch-archaeologist + variant-hunter +
  fuzzing-coordinator agents.

See `CHANGELOG.md` for the full release notes.

Lacuna scans **applications**, not repositories. You give it a manifest declaring the 1..N repos that compose your application and the trust boundaries between them, and it returns two reports: an executive narrative of risk and a technical catalog of findings, exploit primitives, and composed attack chains.

It is built around four ideas, in order of importance:

1. **Hypotheses are the unit of work; findings are what survives validation.** Specialized hunter agents form claims about where vulnerabilities probably are. A validator agent runs a red/blue dialectic on each one — bounded by rounds, not tokens — and either promotes it to a finding (with evidence) or refutes it (with reasoning). In v2, a skeptic agent then re-reviews every confirmed finding adversarially.
2. **Primitives and chains beat severities.** Every confirmed finding contributes one or more *attacker primitives* (capabilities with prerequisites and effects). A chain-builder continuously composes primitives into multi-step attack paths across repos. v2 runs it incrementally (every 5 new primitives) and re-opens hunters when chains expose new starting states.
3. **The knowledge graph is the agent's memory; the transcript is scratch.** A SQLite KG holds findings, hypotheses, primitives, chains, evidence, observations, capabilities, weird compositions, minimal repros, coverage gaps, and an event log. Anthropic's documented context-management techniques (compaction, tool-result clearing, the memory tool, sub-agent isolation, just-in-time retrieval) are wired up explicitly so that hours-long scans stay coherent.
4. **Tools are deterministic; agents are speculative.** Three MCP servers (`lacuna-recon`, `lacuna-kg`, `lacuna-dast`) give agents structural answers without forcing them to grep. Recon tools return summaries and handles, not file contents. v2 grows the recon surface from 26 to 41 tools — including the inter-procedural data-flow engine, callgraph reachability oracle, git history tools, custom semgrep, test-coverage oracle, state-machine extractor, gadget catalog, and trust-shadow analyzer.

## What's in this repo

```
lacuna/
├── Dockerfile                # Container image, multi-stage
├── pyproject.toml            # Python package — version is dynamic, read from src/lacuna/__init__.py
├── CHANGELOG.md              # Version history
├── bitbucket-pipe/           # Bitbucket Pipe definition + entrypoint
├── src/lacuna/               # Python: KG, flow engine, MCP servers, oracles, hooks, harness, reports
│   ├── flow/                 # Inter-procedural taint engine
│   ├── precision/            # Precision static analysis: integer range, lifetime, format-string, type-confusion
│   ├── dynamic/              # Sanitizer builds, libFuzzer wrapper, angr symex, differential parsers
│   ├── patches/              # Patch-essence extraction + variant propagation, CVE mapper
│   ├── oracles/              # sqlmap / ysoserial / gopherus / JWT forensics / ffuf wrappers
│   ├── tools/                # MCP recon/kg/dast servers + git_history, custom_semgrep, test_coverage, state_machine, gadget_catalog, trust_shadow, OAuth/mass-assignment/JS-bundle/CI-config/JWT/CVE tools
│   ├── dast/                 # Includes Playwright runner for DOM-XSS / postMessage / DOM clobbering, GraphQL introspection, shadow surface discovery
│   ├── cache/                # Tool-call result caching layer
│   ├── diff/                 # Diff scope calculator + delta module for risk timeline
│   └── ...
├── .claude/                  # Claude Code config: CLAUDE.md, agents, skills, hooks, settings
│   ├── agents/               # Hunters (injection, crypto, authn-authz, OAuth, mass-assignment, SSRF, GraphQL, business-logic, cross-service, deserialization, race-toctou, memory, CI-supply-chain) + recon + validator + chain-builder + skeptic + trust-shadow-analyzer + patch-archaeologist + variant-hunter + fuzzing-coordinator
│   └── skills/               # Skills incl. weird-machine, minimal-repro, cross-hunter-observations, vulnerability-researcher, trust-the-fuzzer, inductive-variant-hunting, counterfactual-reasoning, patch-suggestion, failing-test-generation
├── examples/                 # Sample manifest + bitbucket-pipelines.yml
├── tests/                    # Unit tests for KG, hooks, MCP servers, flow engine
└── docs/
    ├── ARCHITECTURE.md       # System design
    └── CONTEXT_STRATEGY.md   # Mythos-style context management deep-dive
```

## Quick start (ad-hoc)

```bash
# Build the image
docker build -t lacuna:dev .

# Run a scan
docker run --rm \
  -v "$PWD/examples/app.lacuna.yaml:/workspace/app.lacuna.yaml:ro" \
  -v "$PWD/reports:/reports" \
  -e AZURE_FOUNDRY_ENDPOINT="https://<your-foundry>.services.ai.azure.com/anthropic" \
  -e AZURE_FOUNDRY_KEY="<key>" \
  -e BITBUCKET_USERNAME="<user>" \
  -e BITBUCKET_APP_PASSWORD="<password>" \
  -e LACUNA_MODE="sast" \
  lacuna:dev scan --manifest /workspace/app.lacuna.yaml
```

For `sast+dast` mode, set `LACUNA_MODE=sast+dast` and populate the `dast:` section of the manifest.

For **diff mode** (PR-scoped scanning):
```bash
docker run --rm \
  -v "$PWD/examples/app.lacuna.yaml:/workspace/app.lacuna.yaml:ro" \
  -v "$PWD/reports:/reports" \
  -e AZURE_FOUNDRY_ENDPOINT="https://<your-foundry>.services.ai.azure.com/anthropic" \
  -e AZURE_FOUNDRY_KEY="<key>" \
  -e BITBUCKET_USERNAME="<user>" \
  -e BITBUCKET_APP_PASSWORD="<password>" \
  -e LACUNA_MODE="diff" \
  -e LACUNA_DIFF_BASE="main" \
  -e LACUNA_DIFF_HEAD="feature-branch" \
  lacuna:dev scan --manifest /workspace/app.lacuna.yaml
```

Reports land in `/reports/`.

## Quick start (Bitbucket Pipe)

In your application's primary repo:

```yaml
# bitbucket-pipelines.yml
pipelines:
  custom:
    nightly-security-scan:
      - step:
          name: Lacuna application scan
          services: [docker]
          script:
            - pipe: docker://your-registry/lacuna:3.1.1
              variables:
                LACUNA_MANIFEST: 'app.lacuna.yaml'
                LACUNA_MODE: 'sast'
                # For PR-scoped scans:
                # LACUNA_MODE: 'diff'
                # LACUNA_DIFF_BASE: 'main'
                # LACUNA_DIFF_HEAD: '${BITBUCKET_PR_DESTINATION_BRANCH}'
                AZURE_FOUNDRY_ENDPOINT: $AZURE_FOUNDRY_ENDPOINT
                AZURE_FOUNDRY_KEY: $AZURE_FOUNDRY_KEY
                BITBUCKET_USERNAME: $BITBUCKET_USERNAME
                BITBUCKET_APP_PASSWORD: $BITBUCKET_APP_PASSWORD
                LACUNA_FAIL_ON: 'critical'
          artifacts:
            - reports/**
```

See `examples/bitbucket-pipelines.yml` for a more complete configuration.

## Configuration

### Required environment

| Variable | Purpose |
|---|---|
| `AZURE_FOUNDRY_ENDPOINT` | Anthropic-compatible Foundry endpoint URL |
| `AZURE_FOUNDRY_KEY` *or* `AZURE_FOUNDRY_AAD_TOKEN` | Auth — key or AAD bearer |
| `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD` *or* `BITBUCKET_ACCESS_TOKEN` | Repo cloning |

### Optional environment

| Variable | Default | Purpose |
|---|---|---|
| `LACUNA_MODE` | `sast` | `sast`, `sast+dast`, or `diff` |
| `LACUNA_MANIFEST` | `app.lacuna.yaml` | Path to manifest, relative to workspace |
| `LACUNA_FAIL_ON` | `critical` | `none` / `critical` / `high` / `medium` |
| `LACUNA_MODEL_OPUS` | `claude-opus-4-7` | Deployment name in Foundry |
| `LACUNA_MODEL_SONNET` | `claude-sonnet-4-6` | Deployment name in Foundry |
| `LACUNA_MODEL_HAIKU` | `claude-haiku-4-5` | Deployment name in Foundry |
| `LACUNA_WALL_CLOCK_HOURS` | `4` | Hard cap per scan |
| `LACUNA_BUDGET_USD` | `50` | Estimated spend cap |
| `LACUNA_MAX_PARALLEL_SUBAGENTS` | `8` | Concurrency |
| `LACUNA_DIFF_BASE` | `main` | Base ref for diff mode |
| `LACUNA_DIFF_HEAD` | `HEAD` | Head ref for diff mode |
| `LACUNA_DIFF_MAX_DEPTH` | `3` | Max import hops for diff scope |
| `LACUNA_FUZZ_BUDGET_MINUTES` | `60` | Dynamic fuzzing budget |
| `LACUNA_REPORTS_DIR` | `/reports` | Output directory for reports |

## Persistence

The knowledge graph is **ephemeral**: a fresh SQLite database is created at the start of each scan and lives only for that scan. 

**Risk-timeline mode** (3.1.0): When enabled, the KG records `scan_runs` and `finding_provenance` tables to track findings across scans. The delta module computes new, fixed, persisted, and regressed findings between runs, enabling "what changed since last time?" queries and CI risk trending.

## Architecture

The design documents in `docs/` are the canonical source:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System architecture: phases, agent topology, tool catalog, knowledge graph schema, report structure.
- [`docs/CONTEXT_STRATEGY.md`](docs/CONTEXT_STRATEGY.md) — Mythos-style context management deep-dive: compaction, context editing, memory tool, sub-agent isolation, just-in-time retrieval, the validator's red/blue dialectic, the chain-builder's pure-primitive context.

### v3 capability layers

v3 organizes its new capabilities into five layered modules:

| Layer | Module | What it does |
|---|---|---|
| 2 | `src/lacuna/precision/` | Precision static analysis: `integer_range`, `lifetime` (UAF), `format_string`, `type_confusion`, `allocator_map`. Output: `precision_findings` — high-confidence leads hunters convert into hypotheses. |
| 3 | `src/lacuna/dynamic/` | Dynamic confirmation oracles: `sanitizer_build` (ASan/UBSan), `fuzzer` (libFuzzer harness wrapper + crash minimization), `symex` (angr subprocess), `differential` (multi-parser HTTP/URL/JSON oracle for smuggling and parser-confusion CVEs). |
| 4 | `src/lacuna/patches/` | Patch-diff and variant search: `patch_essence` extracts the bug-class abstraction from a fix commit and generates a semgrep-style propagation rule; `propagate_pattern` runs it across the codebase to find sibling vulnerable sites. |
| 5 | `.claude/skills/` | Researcher mindset, encoded: `vulnerability-researcher`, `interesting-input`, `trust-the-fuzzer`, `adversary-pricing`. |
| Agents | `.claude/agents/` | Three new: `patch-archaeologist` (mines git history for incomplete fixes), `variant-hunter` (auto-spawned per confirmed finding), `fuzzing-coordinator` (decides what to fuzz under wall-clock budget). |

## Status

Version 3.1.1. Production-shaped but expect rough edges. Some
oracles (libFuzzer, angr symex, ysoserial, sqlmap, gopherus, Playwright)
are best-effort wrappers around external tooling — they fail loudly when
their dependencies are missing rather than silently degrading. Issues,
contributions, and adversarial test cases welcome.

Limits worth knowing about up front:

* The data-flow / taint engine is intra- and inter-procedural for the
  languages tree-sitter handles, but it does NOT model framework magic
  (Spring AOP, Rails autoloading, JS dynamic imports) — assume some
  blind spots there.
* The WHATWG URL differential parser is an approximation, not a spec
  implementation. It's tuned to surface the divergences that exploit
  parser-confusion CVEs, not to be bit-perfect.
* The dollar-budget cap (`LACUNA_BUDGET_USD`) is enforced via the
  agent's own `token_cost_usd` accounting, not an Anthropic billing
  query. Treat it as a soft cap.

## License

Apache-2.0. See [LICENSE](LICENSE).
