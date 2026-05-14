# Lacuna

> Agentic, multi-repo, application-level security scanner. Mythos-style behavior on top of Claude Code. SAST and DAST in one box. Runs as a Docker container — Bitbucket Cloud pipe or ad-hoc.

**v3.0.0** — CVE-grade vulnerability discovery. v3 adds precision static
analysis (integer overflow / use-after-free / format string / type
confusion), dynamic confirmation oracles (sanitizer builds, libFuzzer,
angr symex, parser-differential testing), patch-diff infrastructure
(variant search from your own git history), and the researcher-mindset
skills (`vulnerability-researcher`, `interesting-input`, `trust-the-fuzzer`,
`read-the-fix`, `adversary-pricing`) plus three new agents
(`patch-archaeologist`, `variant-hunter`, `fuzzing-coordinator`). See
`CHANGELOG.md` for the full v3 entry.

**v2.0.0** — added the from-scratch inter-procedural taint engine
(CodeQL-equivalent), git-history-as-evidence, known-gadget catalog,
deep oracles (sqlmap/ysoserial/gopherus), headless Playwright DAST,
state-machine extraction, custom semgrep per scan, test-coverage-as-oracle,
parallel hunters/validators, speculative re-open, adversarial skeptic
pass, trust-shadow capability mapping, minimal-repro enforcement, and
coverage-aware reporting.

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
├── pyproject.toml            # Python package (v2.0.0)
├── CHANGELOG.md              # Version history
├── bitbucket-pipe/           # Bitbucket Pipe definition + entrypoint
├── src/lacuna/               # Python: KG, flow engine, MCP servers, oracles, hooks, harness, reports
│   ├── flow/                 # NEW v2: inter-procedural taint engine (CodeQL-equivalent)
│   ├── oracles/              # NEW v2: sqlmap / ysoserial / gopherus wrappers
│   ├── tools/                # MCP recon/kg/dast servers + git_history, custom_semgrep, test_coverage, state_machine, gadget_catalog, trust_shadow
│   ├── dast/                 # Includes Playwright runner for DOM-XSS / postMessage / DOM clobbering
│   └── ...
├── .claude/                  # Claude Code config: CLAUDE.md, agents, skills, hooks, settings
│   ├── agents/               # 8 hunters + recon + validator + chain-builder + skeptic + trust-shadow-analyzer
│   └── skills/               # 13 skills incl. weird-machine, trust-shadow-mapping, minimal-repro, cross-hunter-observations
├── examples/                 # Sample manifest + bitbucket-pipelines.yml
├── tests/                    # Unit tests for KG, hooks, MCP servers, flow engine
├── docs/
│   ├── ARCHITECTURE.md       # System design
│   └── CONTEXT_STRATEGY.md   # Mythos-style context management deep-dive
└── scripts/                  # Dev helpers
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

For `sast+dast` mode, set `LACUNA_MODE=sast+dast` and populate the `dast:` section of the manifest. Reports land in `/reports/`.

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
            - pipe: docker://your-registry/lacuna:1.0.0
              variables:
                LACUNA_MANIFEST: 'app.lacuna.yaml'
                LACUNA_MODE: 'sast'
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
| `LACUNA_MODE` | `sast` | `sast` or `sast+dast` |
| `LACUNA_MANIFEST` | `app.lacuna.yaml` | Path to manifest, relative to workspace |
| `LACUNA_FAIL_ON` | `critical` | `none` / `critical` / `high` / `medium` |
| `LACUNA_MODEL_OPUS` | `claude-opus-4-7` | Deployment name in Foundry |
| `LACUNA_MODEL_SONNET` | `claude-sonnet-4-6` | Deployment name in Foundry |
| `LACUNA_MODEL_HAIKU` | `claude-haiku-4-5` | Deployment name in Foundry |
| `LACUNA_WALL_CLOCK_HOURS` | `4` | Hard cap per scan |
| `LACUNA_BUDGET_USD` | `50` | Estimated spend cap |
| `LACUNA_MAX_PARALLEL_SUBAGENTS` | `8` | Concurrency |

## Persistence

The knowledge graph is **ephemeral**: a fresh SQLite database is created at the start of each scan and lives only for that scan. To compare scans, archive the report artifacts (Bitbucket does this automatically) — there is no built-in cross-scan diffing in this version.

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
| 5 | `.claude/skills/` | Researcher mindset, encoded: `vulnerability-researcher`, `interesting-input`, `trust-the-fuzzer`, `read-the-fix`, `adversary-pricing`. |
| Agents | `.claude/agents/` | Three new: `patch-archaeologist` (mines git history for incomplete fixes), `variant-hunter` (auto-spawned per confirmed finding), `fuzzing-coordinator` (decides what to fuzz under wall-clock budget). |

## Status

Initial release. Production-shaped but expect rough edges. Issues, contributions, and adversarial test cases welcome.

## License

See `LICENSE`.
