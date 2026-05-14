# Lacuna — Grumpy Reviewer's Critical Analysis

> *"This is what happens when an LLM writes 30,000 lines of code in one weekend and the README, the Dockerfile, the CHANGELOG, and the manifest all confidently claim it works. Half of it almost does. The other half lies to itself."*

Repo under review: `https://github.com/davnschneidau/lacuna.git`
Reviewer mood: bad.
Date: 2026-05-14.

---

## TL;DR

Lacuna is an *ambitious* agentic, multi-repo SAST+DAST scanner built on top of Claude Code. The architecture document reads beautifully. The skill library is genuinely thoughtful. The KG schema is the best part of the codebase by a wide margin.

And yet — almost every layer of the implementation contains at least one of these classes of defect:

1. **Version chaos.** The repo claims to be 3.0.0 in `pyproject.toml` but identifies itself as 1.0.0 in six other places, 2.0.0 in one, and 3.0.0 in a seventh. There is no source of truth.
2. **Feature theatre.** Subsystems are wired up *almost* to the point of working and then quietly miswired so they never actually fire. The gadget catalog is never seeded. Format-string detection has its args silently stripped. Custom-semgrep language gating reads a key that doesn't exist. The patch propagator's regex fallback can't match the patterns it generates.
3. **Documentation/code skew.** `docs/ARCHITECTURE.md` describes a `scripts/` directory, a top-level `harness.py`, a static `.mcp.json` — none of which exist. The orchestrator instructions assume tool names and exit criteria that the code doesn't actually use.
4. **Tests that don't test.** Many "tests" only assert `isinstance(result, list)` or `assert not crash`. The hooks tests can't run on Windows. The patch-propagation test depends on semgrep being installed on the test runner, but the test would *fail* on the pure-Python fallback.
5. **Security smells in a security tool.** Bitbucket credentials are interpolated into clone URLs without URL-encoding. The post-tool-use hook constructs filesystem paths from raw tool names (a tool named with a `/` writes outside its cache dir). The KG's deduplication is read-then-write with no transaction. Bound checks in the integer-range analyzer rely on attributes that materialized AST nodes never carry.
6. **Heuristic regex masquerading as program analysis.** The precision pack advertises CWE-416 UAF detection; in reality it's a 60-line text-scanner that flags anything looking like `free(x)` followed by `func(x)`. The taint analyzer treats `urlparse(x)` as a sanitizer (which is *exactly* how SSRFs get into production).
7. **The CHANGELOG dates three major versions to the same day** (2026-05-14). That's not a release history; that's a single commit pretending to be three years of work.

If you adopt this as-is, you will get plausible-sounding but unreliable scan reports.

---

## 1. Version-stamping fiasco

Same repository. Same day. Pick a number:

| Location | Version |
|---|---|
| `pyproject.toml` | `3.0.0` |
| `src/lacuna/__init__.py` | `1.0.0` |
| `src/lacuna/__main__.py` (the `version` CLI subcommand) | hardcoded `"Lacuna 1.0.0"` |
| `bitbucket-pipe/pipe.sh` (`LACUNA_VERSION`) | `1.0.0` |
| `bitbucket-pipe/pipe.yml` (`image: lacuna:1.0.0`) | `1.0.0` |
| `examples/bitbucket-pipelines.yml` (pipe URI) | `1.0.0` |
| `src/lacuna/reports/generator.py` (`VERSION = ...`) | `3.0.0` |
| `src/lacuna/reports/sarif_emitter.py` (SARIF driver version) | `1.0.0` |
| `src/lacuna/dast/playwright_runner.py` (`user_agent="lacuna/2.0"`) | `2.0.0` |
| `src/lacuna/tools/dast_server.py` (HTTP `User-Agent`) | `1.0` |
| `README.md` | `3.0.0` |

Seven different version answers across one repository. The CLI literally lies to the user when they ask. The SARIF report tells Bitbucket / GitHub / Jira that they're getting findings from "Lacuna 1.0.0" while the package metadata insists this is 3.0.0. A user trying to pin `image: lacuna:3.0.0` in their pipeline will fail because the published example tag is 1.0.0.

**Fix:** single source of truth. Define `__version__` in one place (`src/lacuna/__init__.py`), import everywhere else, parameterize the Docker tag from CI.

---

## 2. CHANGELOG.md — release archaeology that didn't happen

```
## v1.0.0  – 2026-05-14
## v2.0.0  – 2026-05-14
## v3.0.0  – 2026-05-14
```

Three major releases. Same calendar day. This isn't a release history; it's a coat of paint. The CHANGELOG is either fabricated retrospectively or three breaking-feature releases happened over the course of one afternoon. Either way it tells a downstream user nothing about the project's maturity.

Worse: each version section describes "v2 adds parallel hunters" / "v3 adds Layer 2 precision pre-pass" as if they were released to users. They never were. Anyone reading this thinking they can `pip install lacuna==2.0.0` and get a stable older release will be disappointed.

---

## 3. Documentation that lies about the code

`docs/ARCHITECTURE.md` describes:
- A `scripts/` directory — does not exist.
- A top-level `harness.py` — there is a `harness/` package (`src/lacuna/harness/workspace.py`), but no top-level `harness.py`.
- A static `.mcp.json` file — it's generated dynamically in `harness/workspace.py:_write_mcp_config`.
- A "Build order" section that reads as a project plan, not architecture.

`README.md` references a `LICENSE` file and a `scripts/` directory that aren't there. The license is declared as `Apache-2.0` in `pyproject.toml` but the actual `LICENSE` file is missing — so legally, the code has no license, which means *you can't redistribute it*.

`CONTRIBUTING.md` ships with a placeholder email `security@your-org.example`. Six months from now somebody will email that nonexistent address with a real vulnerability and hear nothing back. That's a security tool with no security contact.

`IDEAS.md` is one wall-of-text paragraph. There's no formatting. It's unreadable by humans and uninspectable by future-you.

---

## 4. Packaging & Docker

### `pyproject.toml`

The good: declares dependencies cleanly, has `ruff` + `pytest` config, separates `dev` and `oracles` optional groups. This file is fine.

The not-good: pins `tree-sitter-languages>=1.10.2`. This package is **deprecated** and has no wheels for Python 3.13+. The replacement is `tree-sitter-language-pack`. Anyone installing on a modern Python will fail at build time. There's no workaround in the code.

### `Dockerfile`

```dockerfile
FROM node:20-bookworm-slim AS base
```

This is a Python-first project. Starting from `node:20` for the base stage costs you a multi-hundred-MB Node runtime image you mostly don't need. You then `apt-get install` Python on top of Node. The correct base is `python:3.11-slim` (or `python:3.12-slim`) with Node added if the analysis targets need npm. The current layering is upside down.

Worse, this:

```dockerfile
RUN ... || echo "ysoserial download failed, oracles disabled" 1>&2
RUN python3 -m playwright install --with-deps chromium \
        || echo "playwright install failed" 1>&2
```

You're silently swallowing failures. The image builds green, ships, and the user discovers at scan time that none of the deserialization oracles work. The right behavior is to **fail the build** and let the operator decide whether to drop the affected optional layer.

```dockerfile
RUN pip3 install --no-cache-dir --break-system-packages ...
```

`--break-system-packages` is a footgun in production images. It silently overrides Debian's PEP 668 protection and will fight with apt-installed Python packages on the next minor base bump. Use a venv.

Multi-stage uses `FROM base AS ...` for several stages but the final stage inherits binaries implicitly without `COPY --from=`. It works today but is fragile to reorganization and not what you want documentation-wise.

`CC=clang CXX=clang++` is set globally but `build-essential` (GCC) is also installed; users debugging compile failures get two-toolchain ambiguity for free.

---

## 5. The harness — `harness/workspace.py`

### Shallow clones that the analysis tools require to be deep

```python
subprocess.run(["git", "clone", "--depth", "1", url, dest], check=True)
```

Then in `src/lacuna/tools/git_history.py`:
- `git log -L` requires history.
- `recent_security_commits` needs more than a single tip commit.
- `function_change_history` needs the commit graph.
- `removed_code_in_last_n_days` ditto.
- `patch_archaeologist` agent (whole agent role) is *built around* git history.

Every git-history-aware analysis you advertise is **broken at the harness level**. The harness will clone `--depth 1` and `git_history.py`'s tools will return empty data, which the agents will interpret as "no relevant history" — silently lying to the user.

### Bitbucket creds smuggled into the URL

```python
url = f"https://{user}:{pw}@bitbucket.org/{ws}/{slug}.git"
```

Three problems:
1. **No URL encoding.** A `@` or `:` or `/` in the app password breaks the URL. Bitbucket app passwords historically include `/`. This will simply fail to clone with a confusing error.
2. **Process listing leak.** `subprocess.run(["git", "clone", url, ...])` puts the credentials in `argv`. Anyone with `ps` access on the runner sees them. The right mechanism is `GIT_ASKPASS` or a credentials helper.
3. **No fallback for the access-token variant.** The variable matrix in `pipe.yml` includes `BITBUCKET_ACCESS_TOKEN` but `_clone_repos` only ever consults the user/password pair.

### Env knobs documented but never enforced

The README and `pipe.yml` document `LACUNA_BUDGET_USD` and `LACUNA_MAX_PARALLEL_SUBAGENTS` and `LACUNA_WALL_CLOCK_HOURS`. The first is parsed and never enforced anywhere in the codebase — *no actual cost ceiling exists*. The second is set in the env passed to Claude Code but the orchestrator agent is the only thing that respects it, on an honor system. The wall-clock is parsed in `__main__.py:scan` but nothing actually wraps `run_scan` in a timeout, so a runaway scan will overshoot.

### `subprocess.run(... env=os.environ.copy())`

The harness copies the *entire* parent environment into the Claude Code subprocess. That means any secret you have lying around (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`) is handed to a long-running LLM process that can `os.environ.read()` in tool calls. There's no whitelist. For a security tool, this is embarrassing.

---

## 6. Knowledge graph — `src/lacuna/kg/`

This is the best part of the codebase. The schema is well-thought-out. The dataclasses are clean. The migration path (v1 → v2 → v3 tables) is at least *attempted*. With that out of the way:

### `_ulid()` returns a UUID4 hex slice. It is not a ULID.

```python
def _ulid() -> str:
    return uuid.uuid4().hex[:26]
```

ULID = Universally Lexicographically Sortable IDentifier. It encodes a timestamp prefix so IDs sort by creation order. This function does not do that. It returns 26 hex characters of randomness. IDs are not sortable. The misnomer suggests the author knew ULID was the right answer and just shipped a fake one.

### Read-then-write deduplication, no transaction

```python
def add_hypothesis(self, h: Hypothesis) -> str:
    existing = self._conn.execute(
        "SELECT id, seen_by FROM hypotheses WHERE shape=? AND repo=? "
        "AND file=? AND ABS(line-?) <= 5", (h.shape, h.repo, h.file, h.line)
    ).fetchall()
    if existing:
        # ... merge
    else:
        # ... insert
```

Two concurrent hunters writing the same hypothesis at the same line each see "no existing" and both insert. The dedup invariant the test suite asserts is enforced only by lucky timing. Wrap the SELECT and INSERT in a `BEGIN IMMEDIATE` transaction or use a UNIQUE index plus `INSERT ... ON CONFLICT DO UPDATE`. The CLAUDE.md document literally promises the dedupe is reliable for parallel hunters. It isn't.

### `add_finding` and `update_hypothesis_status` use separate `tx()` blocks

If the process crashes between the two writes, you end up with an orphaned `finding` row whose hypothesis is still `pending`. The reports include the orphan finding but the hypothesis status query shows it unresolved. Inconsistent state. Same fix: one transaction.

### `seed_gadgets()` is never called

`src/lacuna/tools/gadget_catalog.py` defines a `seed_into_kg()` that loads ~21 hand-curated gadget entries (Java RCE classes, Python pickle reducers, Node prototype-pollution shapes, etc.). The orchestrator's CLAUDE.md says:

> Phase 0 — Bootstrap … run `python3 -c "from lacuna.tools.gadget_catalog import seed_into_kg; ..."`

That is, the orchestrator is told *via prose* to remember to bootstrap the catalog. There's no hook, no startup wire-up, no `session_start` action that does it for them. If the orchestrator agent forgets — and it will, because it's an LLM that just got 12 KB of context — then `known_gadgets` returns empty results for the rest of the scan and validators silently lose their gadget intelligence.

Fix: call `seed_into_kg()` in `hooks/session_start.py`.

### `repos_involved` is a comma-joined string

```python
repos_involved: str   # "repo-a,repo-b"
```

…and it's split back via `.split(",")` on read. Any repo with a comma in its name corrupts everything. Also: the SARIF emitter does:

```python
"uri": (finding.get("repos_involved") or "").split(",")[0]
```

So the SARIF location URL points to the first repo's slug, not a file path. SARIF consumers (Bitbucket, GitHub) expect a `physicalLocation.artifactLocation.uri` that resolves to source. They'll fail to render the finding in context.

### `chain_candidates` table is write-only

`hooks/pre_compact_flush.py` writes `chain_candidates` rows whenever the orchestrator emits a `<chain-candidate>` block before compaction. Then… nothing reads them. The `chain-builder` agent reads `kg.list_primitives()` directly. The reports don't surface chain_candidates. The whole table is dead storage that grows unbounded.

### `memory_adapter.py` does an O(N) walk for an O(1) fetch

```python
for h in self.kg.list_hypotheses():
    if h["id"] != hid:
        continue
    # render this one
```

Loads every hypothesis to render one. On a large scan with hundreds of hypotheses, the memory adapter does N walks per render, which itself happens dozens of times per agent run. The KG client has `get_hypothesis(hid)` already; use it.

---

## 7. Recon MCP server — `src/lacuna/tools/recon_server.py`

This is the largest single file in the codebase (~1.7 KLOC) and it does *everything* — inventory, AST queries, taint paths, code excerpts, git history wrappers, dependency parsing, framework detection, custom semgrep, secrets, IaC, the kitchen sink. The cohesion is poor; the bugs cluster.

### `_tool_data_sinks` builds, then discards, an intermediate

```python
flat = {...}             # builds a dict
flat_single = {...}      # then immediately rebuilds and overwrites
return {"sinks": flat_single}
```

`flat` is dead code. Either it was an earlier version someone forgot to delete, or it's an attempt at fallback that doesn't fire. Either way, it bloats the diff and confuses the reader.

### `_tool_fetch_payload` is defined twice in the same file

A literal copy-paste — two `def _tool_fetch_payload(...)` definitions in the same module. The second one wins (Python's last-write semantics) but the first one is dead code that future editors will trip over.

### Cross-repo call detection: naive substring match

```python
if other_repo.name in import_path:
    cross_calls.append(...)
```

This is grep-quality reasoning. `auth-svc` will "call" `auth-svc-deprecated`. `users` will "call" `users-batch-importer`. The false-positive rate is high enough that downstream chain-building leans on garbage edges.

### `_tool_service_map` re-parses its own output

`_tool_service_map` calls `_tool_cross_repo_calls`, gets the result, **serializes it to JSON**, parses it back, and uses that. Pure round-trip waste; both functions live in the same module and have direct access to each other's data.

### `_extract_dep_hint` queries a non-existent `dependencies` table

```python
self.kg._conn.execute("SELECT name, version FROM dependencies WHERE repo=?", ...)
```

There is no `dependencies` table in `kg/schema.sql`. The exception is caught and the result is silently empty. Anyone reading the code believes dep-hints are populated and they're not.

### Manifest loading is uncached

`_load_manifest` re-reads and re-parses YAML on every tool call. With the orchestrator + hunters all calling recon tools dozens of times, the same file gets re-parsed hundreds of times per scan. Trivial to cache.

### `WORKSPACE` captured at module import

```python
WORKSPACE = Path(os.environ.get("LACUNA_WORKSPACE", "/workspace"))
```

Captured **at import time**, not at call time. If anything in the harness mutates `LACUNA_WORKSPACE` after the MCP server is imported, the variable lags. In practice MCP servers are spawned in their own subprocesses so it's not catastrophic, but it's still smelly.

### Dependency-graph parsers: regex Maven and silent fall-throughs

The Cargo parser checks for `[dependencies.foo]` but the check accidentally matches plain `[dependencies]` too. The Maven `pom.xml` parser uses regex on XML. Most parsers wrap `json.loads` / `yaml.safe_load` in a bare `except Exception: pass`, hiding all errors and silently producing partial dependency graphs.

### `_tool_ast_query` builds on `tree-sitter-languages` (deprecated)

Mentioned above. The whole AST query tool is one PyPI release away from breaking.

### `_tool_data_sources` returns wrong source-kind for non-Python

```python
for lang, source_re in PATTERNS.items():
    ...
    kind = lang   # e.g. "python" or "javascript"
```

`_tool_data_sinks` doesn't make this mistake (it returns `sql_exec`, `command_exec`, etc.). The two functions have inconsistent semantics — the rest of the code base treats `source_kind` as a *category* (http_request_param, env_var, file_read) but here it's bound to the *language* the source happens to live in. Downstream `data_flow_paths` filters by `source_kind="http_request_param"` and gets nothing because no source is tagged that way for JS/Go/Java.

### `_tool_custom_semgrep_scan`: detected languages always empty

```python
def _tool_custom_semgrep_scan(self, args):
    lang_stats = self._tool_language_stats(...)
    detected = lang_stats.get("handles", [])     # <-- key never exists
    ...
```

`_tool_language_stats` returns `{"facets": {...}}`. It never returns `"handles"`. So `detected` is always `[]`, the language-rule branch never fires, and the only rules that ever run are the global ones. Custom semgrep is half-installed.

### `LANGUAGE_RULES` in `custom_semgrep.py` only has Python entries

Even if `detected` were correctly populated, `LANGUAGE_RULES` contains no entries for JavaScript, Go, Java, C#, Ruby, or Rust. The "tailored ruleset per language" advertised in the docs is a Python-only feature.

### `_rule_express_no_helmet` is wrong

```python
- pattern-not-inside: |
    const $APP = express()
    ...
    $APP.use(helmet(...))
```

`pattern-not-inside` finds matches that aren't inside a region. The intent here is "flag Express apps that don't use Helmet" — but the implementation matches `express()` patterns that aren't inside an `express()` block, which is essentially every `express()` call ever written. False positives everywhere.

---

## 8. KG MCP server — `src/lacuna/tools/kg_server.py`

### Redundant import inside `call_tool`

```python
from lacuna.kg import KG, Chain, Finding, ...  # at top
...
def call_tool(self, ...):
    from lacuna.kg import open_kg              # again, inside
```

Either everything goes at module top, or everything is deferred to inside `call_tool`. Mixing both is just sloppy.

### `kg.read.capability_graph` has no pagination

Returns the entire capability graph in one MCP response. On a large scan (50 capabilities × 30 edges average) this is a several-KB response. The orchestrator's context can fit it, but multiple capability-graph reads compound. A `limit`/`offset` argument is the obvious fix.

### Tool names use dots

```
kg.read.application_model
kg.read.observations
kg.write.hypothesis
```

MCP technically allows dots in tool names, but several MCP clients (notably some VSCode-style implementations) treat dots as namespace separators with their own semantics. Flat snake_case is safer. Compare against the recon server, which uses `_tool_data_sources` / `data_sources` — that one is flat. The two MCP servers are inconsistent with each other.

### Missing `required` fields in input schemas

Several `kg.read.*` tool definitions omit `required: [...]` even when the implementation will crash without an argument. The MCP client won't pre-validate, so the agent will discover via runtime exception that it should have passed `hypothesis_id`.

---

## 9. DAST MCP server — `src/lacuna/tools/dast_server.py`

### Hardcoded UA + placeholder host

```python
"User-Agent": "Lacuna/1.0",
...
"https://your-org.example/lacuna"
```

A scanner that introduces itself as `Lacuna/1.0` while the package says 3.0.0 will confuse anyone reading their target's access logs.

### `_t_endpoint_enum` decides JSON-vs-YAML by first character

```python
is_json = spec_text.strip().startswith("{")
```

A YAML file starting with `{}` flow-style is misclassified. A JSON file with a leading BOM byte is misclassified. The cost is trivial — try JSON, fall back to YAML — and it's not implemented.

### `_t_crawl` uses `list.pop(0)`

O(n) per pop. For a 10k-URL crawl that's quadratic time. Use `collections.deque` and `popleft()`.

The same function reads only the first 2 KB of HTML when extracting links. Real apps put their navigation menus at the bottom of the page. The crawler will miss the majority of navigable links by design.

### `_glob_match` is just a prefix match

```python
def _glob_match(pattern: str, host: str) -> bool:
    if pattern.endswith("*"):
        return host.startswith(pattern[:-1])
    return pattern == host
```

The configuration uses globs like `"*.staging.example.com"` (leading wildcard). `_glob_match` will not match these. The "leading-wildcard" branch isn't implemented. So the configured allow-list works *only* for exact hostnames. Users will write `"*.staging.example.com"`, see no requests fire against it, and blame the network.

### OAuth flow does an `and`/`or` gymnastics

```python
client_secret = (
    flow.get("client_secret_env")
    and os.environ.get(flow["client_secret_env"], "")
    or ""
)
```

This is a Python idiom that returns `""` if `client_secret_env` is unset, or `""` if the env var is empty, or the env value otherwise. It works by accident. Use `os.environ.get(flow.get("client_secret_env", ""), "")` or just a two-line `if`.

### `_t_oracle_gopherus` declares `command` required, implementation makes it optional

The MCP `inputSchema` says `required: ["command"]`. The function body has `command: str | None = None`. An agent passing `null` will be rejected at the schema layer; an agent omitting it will be rejected at the schema layer; the optional path can never execute. Either lift the schema or remove the `None` default.

### `_t_oracle_ysoserial` doesn't verify the JAR exists

```python
jar = os.environ.get("YSOSERIAL_JAR_DEFAULT")
subprocess.run(["java", "-jar", jar, ...])
```

If the JAR is missing (the Dockerfile *silently swallows* a failed `curl`), this just errors at runtime with `Unable to access jarfile`. The tool surfaces "deserialization oracle failed" without telling the user that the oracle is **not installed**. The right answer is a startup check that disables the oracle and logs a clear "ysoserial unavailable; deserialization confirmation disabled" once.

### `_t_header_test`'s host-injection probe samples first 2 KB

Same bug as `_t_crawl`. If the host header reflection appears later in the response body (in a footer link, in a metadata block), the probe doesn't notice. Combined with the next bug, the false-negative rate on header smuggling is significant.

### HTTP smuggling probe limited by `httpx`

```python
# Note: httpx normalizes conflicting Content-Length headers.
```

Buried as a comment. `httpx` collapses duplicate `Content-Length` headers before they reach the wire. The whole point of the smuggling probe is to send conflicting CL. Using `httpx` here means the wire payload never has conflicting headers, so the target server can't desync, so the probe never positively detects smuggling.

The tool documentation that agents see doesn't warn them about this limitation. They'll happily run the probe, see negative results, and conclude the target is safe.

---

## 10. Flow engine — `src/lacuna/flow/`

The taint engine is one of the more important pieces of Lacuna — every hunter is told to *prefer `data_flow_paths` over grep*. Let's check what's actually under the hood.

### `parse_with_tree_sitter` flattens to a list

```python
def parse_with_tree_sitter(path, lang):
    captures = run_query(...)
    nodes = []
    for cap in captures:
        nodes.append(Node(kind=..., ...))
    return Node(kind="Module", children=nodes)
```

The result is a one-level tree: Module → flat list of Functions, Calls, Assigns. The parent-child relationships that tree-sitter actually parsed are thrown away. So:
- Call graph can't tell `foo()` inside class A from `foo()` inside class B.
- Assignments lose their enclosing function context.
- The matching of captures to nodes is O(N²) inside a nested loop.

This is the foundation everything else builds on. Building a "call graph" from a flat list of function calls is barely better than `grep -n '('`.

### `_ast_dump_short` for `BinOp` loses the operator

```python
return f"{_ast_dump_short(left)} <op> {_ast_dump_short(right)}"
```

Every `a + b`, `a * b`, `a | b`, `a or b` is collapsed to `"<op>"`. So:
- The integer-range analyzer's check for multiplicative overflow (`re.search(r"\*", size_expr)`) **always fails** for Python AST nodes. The `is_multiplicative` flag is false-by-construction on Python.
- The taint engine's sanitizer matching looks for `quote(...)`, `escape(...)` etc. but if the sanitizer is on one side of a `BinOp`, the `<op>` placeholder hides which side it was.

### `parse_python_file` silently swallows everything

```python
try:
    return parse(...)
except (SyntaxError, OSError):
    return None
```

A scan over a real repo encounters real syntax errors. Each one becomes a silent skip. The agent's view of the codebase is incomplete and it has no way to know.

### `callgraph.py`: Windows-incompatible module names

```python
module_name = str(path.relative_to(root)).removesuffix(path.suffix).replace("/", ".")
```

On Windows, the relative path uses `\`. The replace converts forward slashes only. Windows users (the OS this very repo is being analyzed on) get module names like `app\handlers\user.py` → `app\handlers\user`. Nothing downstream matches that. Then again, this whole project's tests can't run on Windows anyway, so the regression won't be caught.

### `_resolve_callee` for methods requires *exactly one* matching `Class.method`

```python
candidates = [f for f in funcs if f.name.endswith(f".{method}")]
if len(candidates) == 1:
    return candidates[0].qualname
return None
```

A method named `validate` in two classes ⇒ no resolution. The call is silently lost from the call graph. Real codebases have lots of these. The call graph's recall is therefore much lower than the architecture document implies.

### Taint engine — `parameterized_sql` sanitizer never fires

```python
SANITIZERS = {
    "parameterized_sql": re.compile(r"\.execute\s*\(\s*[^,]+,\s*\("),
    ...
}
```

This pattern is applied to `Call.name`. `Call.name` is `"cursor.execute"` — *not the whole call expression with args*. The regex looks for the comma-and-paren pattern, which only appears in the args, not in the name. The sanitizer pattern can never match in practice. So every parameterized query is reported as SQL injection.

### `urlparse` is a "url_validate" sanitizer

```python
"url_validate": re.compile(r"\burlparse\b|\burlsplit\b"),
```

**This is a security bug in a security tool.** `urlparse(user_input).geturl()` is the canonical way to leak SSRF — the user controls the netloc, you parse and then `requests.get(...)` the parsed URL, and you go to `http://internal/admin`. The taint engine claims this is sanitized. The hunters that use `data_flow_paths(sink_kind="ssrf")` will get zero hits on URLs that came through `urlparse`. The validator that consults the taint engine will agree "looks safe". You won't find SSRFs in this codebase if it scans itself. Ironic.

### `_rhs_is_sanitized` clears taint if a sanitizer pattern appears anywhere

```python
def _rhs_is_sanitized(rhs):
    for s in SANITIZERS.values():
        if s.search(rhs):
            return True
    return False
```

`tainted_value + escape("safe_unrelated_string")` becomes "sanitized". The pattern only needs to *appear* in the RHS, it doesn't need to wrap the tainted operand. This is the canonical failure mode for taint analyzers built on string matching, and Lacuna does the canonical thing.

### Hard-coded confidence scores

`0.7` for direct hits, `0.6` for inter-procedural. No calibration. No A/B against ground truth. Just numbers. The skeptic agent is supposed to fix this but the skeptic has no way to know whether the input confidence was overcalibrated, so it can't.

### No memoization, no recursion budget enforcement

`_function_returns_taint` can recurse forever on cyclic call graphs. There is a `max_depth` parameter but it's *not enforced* — only consulted on entry, not propagated through inter-procedural calls. Cyclic call graphs (which exist in any non-trivial codebase) get exponential or infinite analysis time.

---

## 11. Precision pack — `src/lacuna/precision/`

This is the v3 marquee feature. Layer 2 precision findings, marketed as "high-confidence leads that hunters convert into hypotheses." Let's check.

### `integer_range.py`

**Every function parameter is treated as `kind="attacker"` taint.** The comment says "refined by data-flow analysis later"; it isn't. An internal helper `def _quux(n):` with all callers passing constants is flagged the moment it does `bytearray(n)`. The false-positive rate on any real codebase is going to be 80%+.

**Bound-check propagation is dead for Python.** `_propagate_bound_checks` reads `branch_node.attrs.get("src_snippet", "")`. Python AST nodes (built by `parse_python_file`) never set `src_snippet`. Only tree-sitter nodes do. So `if n < MAX_SIZE: bytearray(n)` is **not** recognized as bounded in Python.

**`is_multiplicative` always false for Python.** Because `_ast_dump_short` on a `BinOp` returns `"a <op> b"`, no `*` is ever present. So Python integer overflows are always classified `CWE-789 oversized_alloc`, never `CWE-190 int_overflow`. Java/C/C++/Go can catch this because they use tree-sitter and preserve the operator in `src_snippet`. Python can't.

**`new[]` regex matches Java/C++ `new T` but tree-sitter doesn't represent those as Call nodes.** In tree-sitter Java grammar, `new SomeClass(...)` is an `object_creation_expression`, not a `call_expression`. So `_check_allocation` never sees these. The Java integer-overflow detection is checking the wrong AST shape.

**`py_list_mul: re.compile(r"<list_mul>")`** is a regex looking for a literal tag string that nothing ever sets. Dead code shipped to users.

### `lifetime.py`

The docstring promises UAF, double-free, and dangling-pointer detection. The implementation is **a 60-line regex scanner over raw text lines**:

```python
if m := re.search(r"\b(\w+)\s*=\s*((?:\w+\s*\*\s*)?(?:malloc|calloc|...)) ...", line):
```

This is not lifetime analysis. This is `grep -A 5 malloc | grep free | grep -B 0 -A 5 'use of same name'`. It will catch the simplest pedagogical examples and miss everything real:

- Aliasing through function calls? No.
- Pointer arithmetic? No.
- Branch sensitivity? No — a free inside `if (cond)` is treated as free unconditionally.
- The "use-site detection" matches `func(p)` as a use of `p`, including `printf("done with %p", p)` after `free(p)` — which is technically UAF if the pointer value is dereferenced inside `printf("%p", p)`, but reasonable code does this safely with `%p` (just the address).
- After the first UAF finding for a pointer, the code sets `ps.is_freed = False` to "avoid duplicate findings within fn." So if there are *three* uses after free, only the first is reported. In real C the second and third uses might be the actually-exploitable ones.

Marketing this as CWE-416 detection is not honest. It's a UAF *suggestion machine* with high false-positive and false-negative rates.

### `format_string.py`

**Catastrophic bug.** The detection logic looks at `Call` nodes' args:

```python
for call in root.of_kind("Call"):
    args = call.attrs.get("args", []) or []
    if not args:
        continue
```

Materialized tree-sitter `Call` nodes in `ast_parse.py` are constructed with `args=[]` and never populated. So **every tree-sitter Call has empty args**. The check `if not args: continue` means the format-string detection only fires on Python AST nodes (which do populate args). But Python isn't where format-string bugs matter — they matter in C/C++ where `printf(user_input)` is the classic CWE-134.

The whole tool is essentially dead for C/C++/Java/Go.

### `type_confusion.py`

This one is at least text-search based and language-aware. Tolerable. Some specific gripes:

- `_analyze_java` only finds the *first* cast in the 600-char window after a deserialize. If multiple casts follow, only one is reported.
- `_analyze_cpp` hardcodes the list of buffer-derived names: `(buf|data|msg|pkt|packet|payload|body|input)`. A pointer named `bytes`, `raw`, `chunk`, `frame` — invisible.

### `allocator_map.py`

The most honest module in the precision pack. It's intentionally heuristic, it admits as much, and the output is descriptive (counts), not prescriptive (findings). Fine.

---

## 12. Hooks — `src/lacuna/hooks/`

### `pre_tool_use_gate.py` — rate limiting that doesn't

```python
_LAST_REQUEST_TS: dict[str, float] = {}
```

A module-level dict. The hook is invoked as `python3 -m lacuna.hooks.pre_tool_use_gate` — **a fresh subprocess per invocation**. The dict starts empty every time. Rate limiting across hook calls is impossible with this design. The dict doesn't persist across processes.

Then:

```python
time.sleep(remaining_seconds)   # while holding the KG connection
```

Blocks the SQLite connection. Concurrent hook invocations queue up on SQLite's writer lock. So your rate-limit-spreading actually serializes the entire pipeline.

The check `tool_name.startswith("lacuna-dast")` fails for the actual tool name `mcp__lacuna-dast__http_request` (which is what Claude Code passes). It works against the readable name from the contract, not the wire name. Likely the entire DAST gate is being skipped.

### `post_tool_use_record.py` — path injection

```python
payload_path = str(cache_dir / f"{tool_name}-{h}.json")
```

`tool_name` is whatever the agent passes. If a malicious agent (or a misbehaving one) uses `tool_name = "../../etc/passwd"`, the hook writes a JSON file outside the cache dir. This is a Lacuna-runs-as-root container; that file overwrite is bad. Sanitize `tool_name` before joining paths.

It also writes both the full payload and separate request/response JSON files for DAST HTTP calls. Three on-disk copies of the same data per call.

### `pre_compact_flush.py` — raw SQL through `kg._conn`

```python
kg._conn.execute("INSERT OR REPLACE INTO chain_candidates ...")
```

The hook reaches into a private attribute and inserts directly. Bypasses the KG client API the rest of the codebase uses. Inconsistent abstraction levels — anywhere else in the code, mutations go through `kg.add_*` / `kg.update_*` methods. Here we have raw SQL plus a transaction the client owns. Two consumers, same DB, two conventions.

### `stop_continuation.py` — orchestrator name check is fragile

```python
if agent != "orchestrator":
    return {"decision": "allow"}
```

But `subagent_stop_validate.py` considers `agent in ("orchestrator", "main", "claude")`. So if Claude Code renames the orchestrator to `"main"` (which it does for some configurations), `stop_continuation` allows the stop and `subagent_stop_validate` thinks it's still the orchestrator. Inconsistency.

### `subagent_stop_validate.py` — dead checks

Checks for `fuzz_runs.status = 'running'`. The fuzzer code path writes only `'completed'`, `'timeout'`, `'build_failed'`, `'crashed'`. There is no `'running'` state. The check is dead.

Reaches into `kg._conn` for raw SQL (same encapsulation violation as `pre_compact_flush`).

The CWE allow-list (`CWE-122`, `CWE-125`, `CWE-369`) is hardcoded here. The same list appears in CLAUDE.md, the precision pack, and the validator agent file. Drift between these is *not detected* — change one, the others go stale.

---

## 13. DAST — `src/lacuna/dast/`

### `playwright_runner.py` — listener leak

```python
for url in target_urls:
    page.on("console", lambda m: ...)   # registered each iteration
    page.on("dialog", lambda d: ...)
```

`page.on` *adds* a listener; it doesn't replace. After 100 URLs you have 100 console listeners, each firing on every console message. Memory leak. Use `page.once` or register once outside the loop.

### `oob_client.py` swallows misconfiguration

```python
def poll(self):
    if not self.collector_url:
        return []
```

If the OOB collector is misconfigured, `poll()` returns "no hits." The validator interprets that as "no out-of-band callbacks, no SSRF confirmation, must refute." Real SSRFs get refuted because we never asked the collector.

### `payloads.py` includes a broken XSS payload

```python
"<style>@import'//lacuna-evil.example/x.css'</style>"
```

This is a CSS import. CSS imports don't execute JavaScript. The `//lacuna-evil.example/x.css` resource is also a comment in CSS, not a URL — `//` starts a single-line comment in some CSS dialects. Either way, this payload doesn't exfil, doesn't run JS, and doesn't do whatever the author thought it would.

A NoSQL payload `[$ne]=1` is syntactically not valid JSON — you'd inject this as a query string parameter, but the file's docstring suggests it's also intended as a body. Half-thought-through.

---

## 14. Patches — `src/lacuna/patches/`

The variant-search idea is good. The implementation has the same regex-as-program-analysis problem as everything else.

### `patch_essence.py` GUARD_PATTERNS for CWE-94

```python
"CWE-94": [re.compile(r"\bast\.literal_eval\b|\bjson\.loads\b")]
```

`json.loads` is listed as a "guard" against code injection. Sure, swapping `eval(json_str)` for `json.loads(json_str)` is a fix. But the GUARD_PATTERNS dict is consulted on *added lines* — any new `json.loads(...)` call in a patch is interpreted as a CWE-94 guard. Patches that *introduce* JSON parsing for unrelated reasons (every other commit ever) are misclassified.

### `propagate.py` regex fallback can't match what `patch_essence` emits

`patch_essence` generates patterns that include the *literal text* of the buggy statement, with identifiers replaced by `$X1`, `$X2`. The regex fallback in `propagate._pattern_to_regex` only handles `$METAVAR` (uppercase) and `...`. It re.escape()s every other character. Multi-line patterns require DOTALL semantics that `.*?` doesn't have without `re.DOTALL`.

Practical result: the test `test_extract_essence_from_real_commit` passes only when semgrep is installed and the AST-aware matcher handles the pattern. Without semgrep, the pattern is `re.escape("return db.query(...) + str(uid)")` with metavars replaced — but the metavars are uppercase, so `uid` (lowercase) doesn't get replaced, and admin.py's `pid` won't match. **The fallback test would fail.**

### Both paths to YAML

`_pattern_from_snippet` builds a YAML block by string concatenation, with f-strings, indented by hand. Any pattern containing a YAML special character (`:`, `&`, `*`, `!`, `|`, `>`, `'`, `"`) breaks the YAML. `yaml.safe_load` will then explode in the propagator's fallback. Use `yaml.safe_dump` to write the rule.

---

## 15. Dynamic — `src/lacuna/dynamic/`

### `sanitizer_build.py`

**CMake build erases project flags.** `-DCMAKE_C_FLAGS=...` *replaces* `CMAKE_C_FLAGS`. Projects that set their own warnings, defines, optimization flags lose all of them. The right approach is `CMAKE_C_FLAGS_INIT` (only the first time) or appending `${CMAKE_C_FLAGS}`.

**Autotools build ignores `work` dir.** The harness creates `work` but the autotools branch runs configure/make inside the repo root. So `_enumerate_binaries(work, repo_root)` finds nothing because the binaries are in `repo_root`. Status=success, binaries=[]. Anything downstream (fuzzer) breaks because there's no library to link against.

**`make -j` unrestricted.** No `-j` cap. On a 2-vCPU 8GB Bitbucket runner, a parallel kernel-module-style make eats memory and OOMs.

**Cargo path uses `+nightly`.** Requires nightly Rust. There's no check that nightly is installed. Fail mode is opaque (cargo's "toolchain not installed" error).

### `fuzzer.py`

**`harness.cc` declares the target as `extern "C"` regardless.** A C++ target with the target function NOT marked extern "C" will fail to link due to name mangling. There's no detection of "is this C or C++?", just assume extern "C".

**Status logic is wrong on timeout-with-crash.**
```python
result.status = (
    "crashed" if result.crashes
    else "completed" if proc and proc.returncode == 0
    else "timeout"
)
```

If `proc` is `None` (timeout) and the libFuzzer process found a crash mid-run, `result.crashes` will be populated from `crash_dir` scan — so status correctly becomes "crashed". But if the process timed out *without* a crash, `proc` is None and `proc.returncode == 0` is False, so we fall to "timeout". OK.

If `proc.returncode != 0` (e.g. libFuzzer aborted on a crash and exited 77), and no crashes were artifact-saved (rare but possible), status becomes "timeout" — wrong, it was an abort.

**`max_total_runs` is just dropped into the cmd as `-runs={N}` only when set**, but libFuzzer requires `-runs=` to be `0` or positive; not handling `None` consistently means callers must pass `int` or `None`. The contract isn't documented.

### `symex.py`

**Driver timeout doesn't actually interrupt angr.** A thread sets an `Event` after timeout_s. The main loop checks the event between `simgr.step()` calls. A single `step()` on a complex state can take minutes. The "60s timeout" is best-case 60 + (one step). Use angr's `AngrTimeout` exception or signal-based interruption.

**Driver writes JSON to stdout via `print(...)`.** angr's verbose logging also goes to stdout (and stderr). Parent does `proc.stdout.strip().splitlines()[-1]` and assumes the last line is JSON. If angr prints a deprecation warning on shutdown, the parser fails. Pipe angr's logging to /dev/null or stderr explicitly.

### `differential.py`

This is one of the better modules. The HTTP CL/CL smuggling test is correct. The duplicate-key JSON detection is correct (subtle: `dict(reversed([("k",1),("k",2)]))` yields `{"k":1}`, picking the "first" value).

Minor gripes:
- WHATWG URL parsing is approximated by replacing `\` with `/`. Real WHATWG has tons of normalization rules (`%2E`, IDN, scheme-specific quirks). Calling this "WHATWG" is generous.
- `_parse_url_naive`'s regex is anchored with `$`, so it won't match URLs with fragments.

---

## 16. Reports — `src/lacuna/reports/`

### `generator.py` — `VERSION = "3.0.0"` declared in the module

Yet another version constant. By now you're not surprised.

### `_format_duration` is misleading

```python
seconds = int(time.time()) - start
```

Subtracts now from scan start. If the report is generated after the scan ends, "duration" includes report-writing time and everything in between. The KG already records a `scan_finished_at` event; use it.

### `_collect_variant_clusters` is O(F × V × H)

```python
for f in findings:                   # F
    for v in variants:               # V (per finding)
        hyp = next((h for h in kg.list_hypotheses() if h["id"] == v["child_hyp_id"]), None)  # H scan
```

`kg.list_hypotheses()` is called inside a doubly-nested loop. For a scan with 100 findings each with 3 variants and 500 hypotheses, that's 150,000 hypothesis fetches. Build a dict once outside the loop.

### `sarif_emitter.py` — `rule_id = f.get("cwes") or f["id"]`

`f["cwes"]` is *parsed JSON*. The KG client deserializes `cwes_json` into a Python list before returning. So `rule_id` is `["CWE-89"]` — a list. Then:

```python
if rule_id not in rules_by_id:        # works (returns False)
    rules_by_id[rule_id] = {...}      # TypeError: unhashable type: 'list'
```

This crashes the SARIF emitter on every finding with a CWE list (most of them). The bug was probably never triggered because the test suite doesn't actually call `emit_sarif`.

### SARIF locations point to repo names, not source files

```python
"uri": (finding.get("repos_involved") or "").split(",")[0]
```

The SARIF spec wants a file path; this gives a repository slug. Bitbucket / GitHub / Jira will fail to link the finding back to source.

### SARIF `tool.driver.version` hardcoded `"1.0.0"`

This is what Bitbucket displays to the user. Per the version-fiasco section, the user installed 3.0.0. The report says they ran 1.0.0. Trust collapses.

---

## 17. `.claude/` configuration

### `settings.json`

`"model": "${LACUNA_MODEL_OPUS}"` — env interpolation. If the env var is unset (which is the default since `pipe.sh` exports defaults *only when called as a pipe*, not necessarily when called locally), the literal string `"${LACUNA_MODEL_OPUS}"` is sent to Claude as the model name. This will be rejected by the API. No fallback default in the settings file.

`subagents.maxParallel: 8` is set here and `LACUNA_MAX_PARALLEL_SUBAGENTS` is set in env. Two sources of truth. Documentation doesn't say which wins.

### CLAUDE.md — phase 0 bootstrap by hope

> Phase 0 — Bootstrap …
> ```
> python3 -c "from lacuna.tools.gadget_catalog import seed_into_kg; print(seed_into_kg())"
> ```

The orchestrator agent is *told via prose* to remember to bootstrap the gadget catalog. That's it. No hook. No startup script. No automatic invocation. If the agent fails to follow the prose instruction, `known_gadgets(...)` returns empty for the rest of the scan. There's no warning, no fallback, no detection. Move this to `session_start.py`.

Same file documents `LACUNA_FUZZ_BUDGET_MINUTES` but I can't find it referenced anywhere in the Python code.

The Stop hook is documented to check `no in-flight fuzz_runs with status=running` — but no code ever writes that status. Dead check.

### Validator agent — broken tool list

`validator.md` lists 30+ tools the agent may call. In step 11 of the procedure:

> Call `kg.write.minimal_repro(finding_id, minimal_payload, minimization_steps)`.

…but `kg.write.minimal_repro` is **not** in the tool list. Same with the `minimal-repro` *skill*, which is referenced in the prose but not listed under `skills:`. The Stop hook checks "every confirmed finding has a minimal_repro" — the validator will be unable to comply, and the orchestrator will be stuck in an infinite stop-rejected loop.

### Skeptic agent uses different YAML conventions

`skeptic.md` declares `allowed-tools:` (kebab-case) while every other agent uses `tools:`. Tool names are short (`kg.read.findings`) instead of the MCP-prefixed form (`mcp__lacuna-kg__kg.read.findings`). Claude Code's parser may or may not accept this — depends on version. Either way it's inconsistent with the rest of the agent files.

### Skill files

`weird-machine`, `red-blue-dialectic`, `chain-construction`, `primitive-extraction` — the skill content is thoughtful. These are the strongest documents in the repo. But:

- The skill on "minimal-repro" is referenced from validator.md but doesn't exist as a SKILL.md.
- Skills are not actually wired up to anything that enforces their use; they're just instruction documents.

---

## 18. Tests — what they cover and what they don't

### Hooks tests can't run on Windows

```python
env = {..., "PATH": "/usr/bin:/bin", ...}
```

Hardcoded Unix paths. The tests will fail to spawn `python3` on Windows. CI on Windows is impossible.

### `test_flow_engine.py` — weak assertions

```python
def test_taint_engine_inter_procedural_recursion_limit(tmp_path):
    ...
    hits = taint_paths(cg, max_depth=3)
    assert isinstance(hits, list)
```

That's not a test of the recursion limit. That's a test that the function returns a list type. The actual recursion behavior is unverified.

```python
def test_python_specific_constructs(tmp_path):
    ...
    hits = taint_paths(cg)
    assert isinstance(hits, list)
```

Same anti-pattern. Doesn't crash → passes. Whether the engine correctly understood f-strings is untested.

```python
def test_taint_engine_respects_sanitizers(flask_app):
    sanitized_hits = [h for h in hits if "safe_endpoint" in h.function]
    assert len(sanitized_hits) == 0
```

The `/safe` endpoint doesn't *have* a sink — it just returns `f"<div>{nq}</div>"` (an f-string, not a known sink). So this test passes whether or not the sanitizer works. It's testing the absence of a sink, not the presence of a sanitizer.

### `test_patches.py` — depends on git binary

```python
_git(repo, "init", "-q", ".")
```

Tests fail in CI environments without git installed. The `extract_essence` API claims to work on raw diff text without git — and there's exactly one test for that path. The git-required path is tested better.

### `test_precision.py` documents broken behavior as "intended"

```python
def test_integer_range_skips_bounded_attacker_input(tmp_path):
    """... The current heuristic may or may not perfectly track this; the test
    documents the *intended* behavior. We allow either zero findings or
    a single low-confidence one — but never a high-confidence one."""
    high_conf = [f for f in result["findings"] if f["confidence"] > 0.65]
    assert not high_conf, "bounded n should never be high-confidence"
```

The test *admits* the bound-check propagation doesn't work and only enforces "don't be high-confidence when wrong." That's not a test — that's documenting the known bug as policy.

### No tests for: harness, recon_server, kg_server, dast_server

The heart of the system has no direct test coverage. Every MCP tool you call lives in one of these files, and none of them have integration tests against a real KG. The KG itself is well-tested. Everything that uses the KG is not.

### Test isolation half-attempted

`conftest.py` `isolate_env` sets env vars per-test but the recon server reads `LACUNA_WORKSPACE` at module import. Once imported, mutating env doesn't help. So tests of recon tools (which thankfully don't exist) would observe stale workspace paths.

---

## 19. Examples & Bitbucket pipe

### `examples/bitbucket-pipelines.yml` — placeholder registry

```yaml
- pipe: docker://your-registry.example.com/lacuna:1.0.0
```

Three problems in one line:
1. Placeholder hostname.
2. Wrong version tag.
3. Use of `docker://` URL form requires explicit Docker support enabled in Bitbucket; the official `pipe:` form is `bitbucket-pipelines:tag` for marketplace pipes or `docker://image` for self-hosted. The example uses the self-hosted form but doesn't tell the user how to push the image.

### `pipe.yml` — `image: lacuna:1.0.0`

Same versioning issue. The example app manifest points at `payments-svc` etc. — fine for an example, but combined with the placeholder Bitbucket workspace `example-corp`, a new user can't even copy-paste the manifest without breaking it.

---

## 20. The cumulative effect

When you tally the issues:

| Class of defect | Count (approximate) |
|---|---|
| Version mismatches | 7 distinct version strings in one repo |
| Subsystems that silently no-op | 5 (gadget seeding, format-string for C/C++, custom-semgrep language gating, regex propagation fallback, lifetime UAF beyond toy cases) |
| Security smells in a security tool | 6+ (credentials in argv, path injection in cache, urlparse as sanitizer, no transactions on dedup, sensitive env to subprocess, broken DAST host allowlist) |
| Broken tests / weak assertions | 7+ |
| Documentation/code drift | 10+ (multiple docs reference files/tools that don't exist or behave differently than described) |
| Hardcoded placeholders left in shipping artifacts | 5 (`your-org.example`, `your-bitbucket-workspace`, `your-registry.example.com`, `lacuna-evil.example`, `security@your-org.example`) |
| Stub features advertised in README/CHANGELOG | At least 3 features (precision UAF, format-string CWE-134, custom-semgrep per-language rules) |

This is **the failure mode of LLM-assisted development without verification**: a sprawling architecture, plausible-looking implementations, a great-looking README, and a 200x reduction in actual functionality compared to what the documentation claims.

A real reviewer in a real bad mood would block this from merging until the version chaos is resolved, the credential-leak fixed, the urlparse-as-sanitizer removed, the format-string args bug fixed, the gadget catalog auto-seeded, the validator agent's tool list completed, and at least the SARIF emitter's crash bug repaired. Then they'd ask for the dead `chain_candidates` table to be removed and for ten more unit tests on the recon and DAST servers before they look at it again.

---

## 21. What's actually good

To be fair to the author:

1. **The KG schema is well-designed.** The separation of hypotheses → findings → primitives → chains is genuinely thoughtful. The exit-criteria pattern is a clean way to encode "what does done look like."
2. **The skill library is the strongest documentation in the repo.** `caveman`, `red-blue-dialectic`, `semantic-pattern-matching`, `weird-machine`, `chain-construction` — these read like field manuals written by someone who has actually done security review. Whoever wrote these knows the domain.
3. **The differential parser oracle is a clever idea, well-executed.** Smuggling and parser-confusion are real and the test cases here are correct.
4. **Mythos-style context management** (PreCompact flush, tool result clearing, subagent isolation, KG as durable memory) is exactly the right mental model for a long-running agentic scan. The implementation has gaps but the design is sound.
5. **The `Hypothesis → Finding → Primitive → Chain` data flow** is the right abstraction for security findings. Most SAST tools collapse this into "issue." Lacuna's tiered model is better.
6. **Bug detection ideas are correct.** Even where the implementations are weak, the *targets* (CL/CL smuggling, type confusion across deserialize, integer overflow into alloc, log4shell pattern, trust-boundary holes, capability graph) are the right priorities for a 2026-era app scanner.

If this codebase were turned over to a competent engineer who systematically fixed the issues above, the bones are good enough to build a real product on. As shipped, it's a demo with a great-looking facade.

---

## 22. Concrete action items in priority order

1. **Single source of truth for `__version__`.** Define once, import everywhere. Fix Docker tag, SARIF driver version, User-Agent strings, pipe.yml image tag.
2. **Fix the format-string detector.** Populate `args` on tree-sitter Call nodes in `ast_parse.py`, or rewrite the detector to walk raw text.
3. **Remove `urlparse`/`urlsplit` from the SSRF sanitizer list.** Replace with explicit allowlist matching.
4. **Wire `seed_into_kg()` into `session_start.py`.** Stop hoping the agent remembers.
5. **Fix `add_hypothesis`'s read-then-write to use a transaction or a unique index.**
6. **Auto-clone with full history, not `--depth 1`.** Or document loudly that git-history analyses are degraded and reduce confidence of their findings accordingly.
7. **Use `GIT_ASKPASS` for credentials, not URL embedding.**
8. **Sanitize `tool_name` in `post_tool_use_record.py` before joining paths.**
9. **Fix `_tool_custom_semgrep_scan` to read `facets` not `handles` from `_tool_language_stats`.**
10. **Drop `tree-sitter-languages`** and migrate to `tree-sitter-language-pack` so the repo can install on Python 3.13.
11. **Repair the SARIF emitter's `rule_id`-is-a-list crash.**
12. **Fix the validator agent's tool list** — add `kg.write.minimal_repro` so the procedure can actually be executed.
13. **Replace the lifetime analyzer's regex scanning** with a proper intra-procedural analysis built on a non-flattened tree-sitter AST, or remove the feature.
14. **Remove silent `try/except: pass`** from dependency-graph parsers and the harness; log instead.
15. **Add tests for the recon and DAST MCP servers**, not just the KG.
16. **Replace placeholder hostnames and emails** with `# TODO: configure` comments or remove them entirely.
17. **Truncate or delete the `chain_candidates` table** if nothing reads it. Or actually wire the chain-builder to read it.
18. **Add a LICENSE file.** The `pyproject.toml` claims Apache-2.0 but there's no LICENSE shipping with the source.
19. **Re-date the CHANGELOG.** A real release history with real dates would help downstream users understand maturity.
20. **Write Windows-compatible tests** or declare Linux-only and CI-gate accordingly.

---

*End of grumpy review. Coffee timer: empty.*
