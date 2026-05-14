# Ideas

Not on the 3.0.0 roadmap — captured here so they aren't forgotten. Each
idea is sized for "one well-scoped PR" rather than "another project."

## Specialist agents

* **Bitbucket MCP integration.** Let the orchestrator read PR diffs and
  past Bitbucket comments via the official MCP server so historical
  review context becomes evidence.
* **OAuth / OIDC specialist.** Mix-up attacks, `redirect_uri`
  smuggling, PKCE downgrade, ID-token confusion, JWKS cache poisoning.
  Composes naturally with `trust-shadow-analyzer`.
* **SAML specialist.** XML signature wrapping (XSW1–7), IdP/SP
  confusion, signature exclusion, comment injection on assertions,
  `RelayState` manipulation.
* **SSRF deep specialist.** What to *do* with a confirmed SSRF: DNS
  rebinding, parser-discrepancy SSRF, redirect-chain bypass, protocol
  smuggling, blind-SSRF timing oracles, IPv6 confusion, IDN
  homoglyphs. Pairs with the existing `gopherus` oracle.
* **Race-condition specialist.** Single-packet attack (TCP last-byte
  sync), session-state TOCTOU, row-locking gaps, distributed-lock
  failures, cache-stampede windows — confirmed via concurrent-request
  bursts through the DAST harness.
* **Mass-assignment specialist.** Rails `strong_params`, Django
  `ModelForm`, Pydantic `model_config`, Hibernate setters. Diff
  client-facing DTOs against ORM models and flag every drift.
* **IDOR matrix specialist.** Crawl every authenticated endpoint as
  user A then re-issue as user B; flag rows where user B sees
  non-404/non-403 responses.
* **XXE / XML specialist.** Entity expansion, parameter entities,
  billion-laughs, OOB XXE via DTD, XPath injection, schema-validation
  bypass.
* **File-upload polyglot specialist.** PHP-in-GIF, SVG-with-JS, ZIP
  slip, polyglot PDFs, content-type sniff confusion. Pairs with a
  magic-bytes polyglot generator (below).
* **NoSQL injection specialist.** MongoDB operator injection, Redis
  `CONFIG`/`EVAL`, Elasticsearch query DSL injection, CouchDB function
  injection.
* **GraphQL specialist.** Introspection enumeration (even when
  "disabled"), nested-query DoS, batch-query rate-limit bypass,
  mutation-vs-query authz drift, persisted-query injection.
* **WebSocket / SSE specialist.** Cross-site WebSocket hijacking,
  auth-on-connect-only handlers, out-of-order message bypass,
  ping-pong abuse for connection persistence past token expiry.
* **Build-system / CI specialist.** `pull_request_target` misuse,
  third-party actions pinned by tag-not-SHA, secret-in-logs from
  `set-output`, cache poisoning, dependency confusion, Dockerfile
  `ADD` from remote URL.
* **PII data-flow specialist.** Not strictly a security agent — a
  data-flow agent that emits a PII map (which endpoints, logs, and
  outbound calls touch which sensitive fields).

## Tools and oracles

* **JS bundle / sourcemap analyzer.** Extract API endpoints, secrets,
  feature flags, internal route tables, and admin-only views from
  production bundles and accidentally-shipped sourcemaps.
* **Wayback / archive shadow-surface miner.** Historical URL lists
  from the Wayback Machine, CommonCrawl, and CT logs to find forgotten
  but still-live endpoints.
* **Encoding-confusion runner.** Systematic percent / double / Unicode
  normalization / IDN homoglyph testing for every text-accepting
  endpoint.
* **HTTP request smuggling deep oracle.** CL.TE, TE.CL, CL.CL,
  `h2c` upgrade smuggling, HTTP/2 header injection. The current
  `_t_smuggling_probe` is a start; an oracle that returns the exact
  poisoning request would be next.
* **JWT forensics + forge tool.** Algorithm confusion, `kid` SQL
  injection, `jwk` header injection, weak-secret cracking, `none`
  acceptance, expired-token acceptance.
* **Magic-bytes polyglot generator.** Files that parse as both X and
  Y, given a target filter + payload type. Pairs with the file-upload
  specialist.
* **Cookie / session-parser confusion tool.** Probe every known
  framework parser quirk (Tornado, Flask, Express, Rails) and report
  which apply to the target.
* **Web cache poisoning probe.** Unkeyed header detection (`Vary`
  gaps), cache-key normalization quirks, cache deception via path
  confusion, ESI injection.
* **GraphQL nested-query bomber + alias enumerator.** Per-server max
  nest depth + alias count as a DoS and authz-bypass oracle.
* **Library-version → known-attack mapper.** Extends the gadget
  catalog with full historical attack records: CVEs, bypass patches,
  known partial-fixes. The "partial-fixes" axis is the high-value one.

## Skills

* **Inductive variant-hunting skill.** When you find one bug, look for
  siblings immediately. Lowers bugs-per-cluster from 1 to N.
* **Counterfactual reasoning skill.** "For this *not* to be a bug,
  what would have to be true?" Forces the validator to articulate the
  precondition for safety.
* **Cargo-cult detection skill.** Near-identical code blocks across
  files probably share a copy-paste origin; if one was fixed, check
  the other.
* **Surprise-as-evidence skill.** Encode the discipline of stopping
  at every "huh, that's weird" moment and investigating.
* **"Read the fix" skill.** *(Already shipped — see
  `.claude/skills/read-the-fix/SKILL.md`.)* Mentioned here for
  completeness.
* **Threat-model-from-architecture skill.** Generate a per-scan
  threat model from the manifest + service map before hunting starts.

## Orchestration modes

* **Multi-model tiering.** Skeptic on Haiku (already), recon and
  hunters on Sonnet, validator escalates to Opus only on round 3+.
  Mixed tier cuts cost ~3–4× with negligible quality loss.
* **`LACUNA_MODE=diff`** — only scan files changed in the PR + their
  transitive imports + the endpoints they touch. Wall-clock drops
  from hours to ~15 min.
* **Authenticated-as-different-users matrix mode.** DAST runs every
  probe as anonymous, user, and admin; flag cells where responses are
  unexpectedly similar.
* **Tool-call result caching layer.** Cache `semgrep_pattern`,
  `dependency_vulns`, `framework_detect`, and the call-graph build by
  `(repo, git_sha, args_hash)`. Pairs well with diff mode.
* **Patch suggestion mode.** For each finding, emit a minimal proposed
  diff — the literal 3-line PR, not "use parameterized queries."
* **Failing-test-case generation.** Emit a failing test in the
  project's test framework asserting the secure behavior.
* **Risk-timeline + delta mode.** Track findings across scans by
  stable ID (location + shape + handler hash); report introduced,
  still-open, fixed, and new findings.
