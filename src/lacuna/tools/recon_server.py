"""
lacuna-recon MCP server.

The reconnaissance toolbelt. Deterministic, application-aware. Agents call
these tools to get structural answers about the application without having
to read or grep files themselves.

Tools follow the "summary + facets + handles" pattern: every result contains
a one-line summary, faceted counts, and a list of handles. Agents can then
call detail-fetch tools on specific handles to drill in. This keeps tool
results small in the agent's context.

For the launch surface we ship:
    app_inventory         dependency_graph    secret_scan
    file_tree             dependency_vulns    iac_scan
    language_stats        framework_detect    git_hotspots
    entrypoints           auth_surface        crypto_usage
    api_surface           authz_checks        serialize_calls
    data_sources          taint_paths         template_engines
    data_sinks            cross_repo_calls    regex_audit
    code_excerpt          service_map         ast_query
    db_schema             fetch_payload       call_graph_at

Several wrap OSS tools (semgrep, trivy, osv-scanner, gitleaks, tree-sitter).
The ones below are implemented end-to-end; framework-detect / authz-checks
/ business-logic-style tools include light heuristics out of the box and
clear extension points.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

server = Server("lacuna-recon")

WORKSPACE = Path(os.environ.get("LACUNA_WORKSPACE", "/workspace"))
MANIFEST_PATH = os.environ.get(
    "LACUNA_MANIFEST_RESOLVED",
    str(WORKSPACE / os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml")),
)
TOOL_CACHE = Path(os.environ.get("LACUNA_TOOL_CACHE_DIR", "/state/tool_results"))
TOOL_CACHE.mkdir(parents=True, exist_ok=True)

# Language detection by extension
LANG_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php",
    ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
    ".cs": "csharp", ".swift": "swift", ".scala": "scala",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".sql": "sql", ".yaml": "yaml", ".yml": "yaml",
    ".tf": "terraform", ".dockerfile": "dockerfile",
}
# Files to always skip
SKIP_PATTERNS = re.compile(
    r"(/\.git/|/node_modules/|/\.venv/|/venv/|/__pycache__/|/dist/|/build/|"
    r"/target/|/vendor/|\.min\.(js|css)$|\.lock$)"
)


# ─── helpers ────────────────────────────────────────────────────────────────

def _load_manifest() -> dict:
    if not Path(MANIFEST_PATH).exists():
        return {}
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f) or {}


def _repo_paths() -> dict[str, Path]:
    """Map repo name → absolute path on disk."""
    out: dict[str, Path] = {}
    manifest = _load_manifest()
    for r in manifest.get("repos", []) or []:
        name = r.get("name")
        if not name:
            continue
        p = WORKSPACE / name
        if p.exists():
            out[name] = p
    # Also include any workspace dir not in the manifest
    if not out and WORKSPACE.exists():
        for child in WORKSPACE.iterdir():
            if child.is_dir() and child.name != ".lacuna":
                out[child.name] = child
    return out


def _iter_files(root: Path, max_files: int = 50000) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if SKIP_PATTERNS.search(str(p)):
            continue
        out.append(p)
        if len(out) >= max_files:
            break
    return out


def _ok(payload: dict) -> list[TextContent]:
    """Wrap a result as MCP TextContent."""
    return [TextContent(type="text", text=json.dumps(payload, default=str))]


def _err(message: str) -> list[TextContent]:
    return _ok({"error": message})


def _stash_payload(name: str, payload: Any) -> str:
    """Store a large payload to the cache dir and return a payload_ref handle."""
    import hashlib
    body = json.dumps(payload, default=str).encode()
    digest = hashlib.sha256(body).hexdigest()[:16]
    p = TOOL_CACHE / f"{name}-{digest}.json"
    p.write_bytes(body)
    return str(p)


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


# ─── tools ──────────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    """Declare the recon tool surface."""
    return [
        Tool(name="app_inventory", description=(
            "Inventory the application: lists repos from the manifest, their "
            "languages, LOC, detected frameworks, and runtime. Always call this "
            "first."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="file_tree", description=(
            "Filtered file tree of a repo. Returns paths + sizes, capped at "
            "max_files (default 500)."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "max_depth": {"type": "integer", "default": 6},
                "max_files": {"type": "integer", "default": 500},
                "include": {"type": "string", "description": "regex"},
                "exclude": {"type": "string", "description": "regex"},
            },
            "required": ["repo"],
        }),

        Tool(name="language_stats", description=(
            "Per-language LOC and file counts for a repo."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="dependency_graph", description=(
            "Parse package manifests (package.json/requirements.txt/go.mod/"
            "pom.xml/Gemfile/Cargo.toml/etc.) and return a normalized dependency "
            "graph with versions."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="dependency_vulns", description=(
            "Run osv-scanner / trivy against the repo's dependencies. Returns "
            "summary + handles to CVE details."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="secret_scan", description=(
            "Run gitleaks against the repo. Returns summary + handles per hit."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="iac_scan", description=(
            "Audit Terraform/CloudFormation/k8s/Dockerfile for insecure configs."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="entrypoints", description=(
            "Find all program entrypoints: HTTP routes, CLI commands, lambda "
            "handlers, queue consumers, cron jobs, event handlers. Framework-aware."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="api_surface", description=(
            "Extract OpenAPI/Swagger/GraphQL/gRPC proto/route definitions."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="auth_surface", description=(
            "Identify auth middleware, login routes, JWT/session/OAuth flows, "
            "token verification points."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="authz_checks", description=(
            "Find authorization check sites: role checks, ownership checks, "
            "ACL lookups."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="data_sources", description=(
            "All untrusted-input sources, classified."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="data_sinks", description=(
            "All dangerous sinks: exec, eval, SQL exec, HTTP clients, FS writes, "
            "template rendering, deserializers."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="taint_paths", description=(
            "Source-to-sink paths via semgrep. Returns summary + handles."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "source": {"type": "string"},
                "sink": {"type": "string"},
            },
            "required": ["repo"],
        }),

        Tool(name="cross_repo_calls", description=(
            "HTTP/gRPC/queue calls *between* repos in the application manifest."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="service_map", description=(
            "Service DAG of the entire application: nodes, edges, transports, auth."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        Tool(name="db_schema", description=(
            "Extract DB schemas from migration files (Rails/Django/Knex/Flyway/"
            "Alembic/Goose)."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="git_hotspots", description=(
            "Files with high churn or recent changes. Often correlated with bugs."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "days": {"type": "integer", "default": 180},
                "top_n": {"type": "integer", "default": 30},
            },
            "required": ["repo"],
        }),

        Tool(name="framework_detect", description=(
            "Detect frameworks (Express, FastAPI, Spring, Rails, Django, etc.) "
            "and surface known footguns for each."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="crypto_usage", description=(
            "All cryptographic API call sites."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="serialize_calls", description=(
            "Serialization/deserialization call sites (pickle, ObjectInputStream, "
            "etc.). Common RCE source."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="template_engines", description=(
            "Template rendering call sites with user-controlled input. SSTI surface."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="regex_audit", description=(
            "Potentially catastrophic regexes (ReDoS)."
        ), inputSchema={"type": "object", "properties": {"repo": {"type": "string"}},
                         "required": ["repo"]}),

        Tool(name="code_excerpt", description=(
            "Pull N lines of context around a file:line location."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "context_lines": {"type": "integer", "default": 30},
            },
            "required": ["repo", "file", "line"],
        }),

        Tool(name="ast_query", description=(
            "Run an arbitrary tree-sitter query against the parsed AST of a repo. "
            "For advanced use; most agents should use the higher-level tools."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "language": {"type": "string"},
                "query": {"type": "string"},
                "max_results": {"type": "integer", "default": 50},
            },
            "required": ["repo", "language", "query"],
        }),

        Tool(name="git_blame_function", description=(
            "Git blame for a line range of a file. Returns author/sha/ts/summary "
            "per line — answers 'who wrote this and when'. Use to investigate "
            "why a check is or isn't present."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "file": {"type": "string"},
                "line_start": {"type": "integer"},
                "line_end": {"type": "integer"},
            },
            "required": ["repo", "file", "line_start", "line_end"],
        }),

        Tool(name="recent_security_commits", description=(
            "Commits in the last N days whose messages match security keywords "
            "(CVE, fix, vulnerability, sanitiz, inject, XSS, SSRF, RCE, etc.). "
            "Bugs cluster near recent security fixes."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "days": {"type": "integer", "default": 365},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["repo"],
        }),

        Tool(name="function_change_history", description=(
            "All commits that touched the code around a file:line. Reveals the "
            "function's evolution and any bug history."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "context_lines": {"type": "integer", "default": 30},
            },
            "required": ["repo", "file", "line"],
        }),

        Tool(name="removed_code_in_last_n_days", description=(
            "Code deleted in the last N days. Deletions of security-relevant "
            "code (auth, validation, sanitization) are leads — they may signal "
            "a recently-introduced regression."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "days": {"type": "integer", "default": 90},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["repo"],
        }),

        Tool(name="commit_message_search", description=(
            "Find commits whose messages match an arbitrary regex pattern."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pattern": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["repo", "pattern"],
        }),

        Tool(name="data_flow_paths", description=(
            "INTER-PROCEDURAL data flow analysis. Runs Lacuna's custom taint "
            "engine: builds a call graph, identifies sources (request params, "
            "env vars, etc.), propagates taint through assignments and function "
            "calls (with sanitizer detection), and reports source-to-sink "
            "paths. Far more accurate than grep/semgrep for cross-file flow. "
            "Optionally filter by source_kind and sink_kind. Results are also "
            "persisted to the KG."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "source_kind": {"type": "string"},
                "sink_kind": {"type": "string"},
                "max_depth": {"type": "integer", "default": 6},
            },
            "required": ["repo"],
        }),

        Tool(name="reachable_from", description=(
            "Callgraph reachability oracle. Returns whether target_function is "
            "reachable from source_function and the shortest path. Use to "
            "REFUTE hypotheses quickly: if a dangerous sink isn't reachable "
            "from any HTTP handler, it can't be exploited through the API."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "source_function": {"type": "string"},
                "target_function": {"type": "string"},
                "max_depth": {"type": "integer", "default": 8},
            },
            "required": ["repo", "source_function", "target_function"],
        }),

        Tool(name="callers_of", description=(
            "All callers of a function (direct or transitive). Useful to find "
            "every entry that reaches a known-dangerous function."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "function": {"type": "string"},
                "transitive": {"type": "boolean", "default": True},
            },
            "required": ["repo", "function"],
        }),

        Tool(name="callees_of", description=(
            "All functions called by a given function (direct or transitive)."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "function": {"type": "string"},
                "transitive": {"type": "boolean", "default": True},
            },
            "required": ["repo", "function"],
        }),

        Tool(name="custom_semgrep_scan", description=(
            "Generate a tailored semgrep ruleset specific to THIS application's "
            "detected frameworks and languages, then run it. More precise than "
            "canned packs because the rules know the app's footguns."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        Tool(name="test_coverage_for_endpoint", description=(
            "Heuristic test coverage: does ANY test file reference this route, "
            "and how many assertions exist near each reference? Untested "
            "endpoints get extra hunter attention."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "route": {"type": "string"},
            },
            "required": ["repo", "route"],
        }),

        Tool(name="test_assertions_for_function", description=(
            "What does the test suite assert about this function?"
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "function": {"type": "string"},
            },
            "required": ["repo", "function"],
        }),

        Tool(name="untested_handlers", description=(
            "Given a list of handler routes, return those with no test references."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "routes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["repo", "routes"],
        }),

        Tool(name="state_machine_extract", description=(
            "Extract a probable finite-state machine from session writes and "
            "redirects in route handlers (e.g. for password reset, OAuth, "
            "multi-step checkout). Returns nodes (states) and edges (transitions) "
            "plus a list of suspected invariant breaks."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        Tool(name="known_gadgets", description=(
            "Query Lacuna's gadget catalog for known exploit chains in this "
            "app's dependency versions. Returns gadget name, impact, PoC "
            "template, references."
        ), inputSchema={
            "type": "object",
            "properties": {
                "language": {"type": "string"},
                "library": {"type": "string"},
            },
            "required": ["language"],
        }),

        Tool(name="trust_shadow_analyze", description=(
            "Build the application's capability graph: who holds which secrets, "
            "keys, IAM roles, signing material; who trusts whom. Writes results "
            "to the KG. Use to find cross-service trust paths that are vulns "
            "even when neither side is buggy in isolation."
        ), inputSchema={"type": "object", "properties": {}, "required": []}),

        # ─── v3: Layer 2 precision static analysis ───────────────────────
        Tool(name="integer_range_analysis", description=(
            "Detect CWE-190/789 integer overflow and oversized-allocation "
            "patterns: allocations whose size expression derives from "
            "attacker-controlled values without bound checks. Writes "
            "precision_findings to the KG. Returns count and a sample."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        Tool(name="lifetime_analysis", description=(
            "Detect CWE-416 use-after-free and CWE-415 double-free patterns "
            "in C/C++/Obj-C. Tracks alloc/free per function. Writes "
            "precision_findings. Returns count and samples."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        Tool(name="format_string_sinks", description=(
            "Detect CWE-134 printf-family with non-literal format and "
            "CWE-117 logger calls that may template-interpret attacker "
            "input (Log4Shell shape). Cross-references log4j-core "
            "version from dependency_graph when available."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "languages": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["repo"],
        }),

        Tool(name="type_confusion_sites", description=(
            "Detect CWE-843 type confusion: casts, type assertions, and "
            "coercions across trust boundaries without runtime guarantees. "
            "Covers Python pickle, Java deserialize+cast, C++ "
            "reinterpret_cast on buffer pointers, Go panic-on-fail "
            "type assertions, TypeScript `as T`."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        Tool(name="allocator_map", description=(
            "Identify what allocators are in use across the codebase: "
            "standard malloc/free, kmalloc with GFP flags, custom "
            "*_alloc/*_free pairs, smart pointers, reference counting. "
            "Metadata for other precision tools — not a finding generator."
        ), inputSchema={
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),

        # ─── v3: Layer 3 dynamic confirmation ────────────────────────────
        Tool(name="sanitizer_build", description=(
            "Auto-detect the project's build system (cmake, make, autotools, "
            "meson, cargo, ...) and run a sanitizer-instrumented build with "
            "ASan + UBSan. Returns built binaries, status, and any sanitizer "
            "warnings caught at compile time. Memoized in KG by repo+git_sha. "
            "PRECONDITION for fuzz_function."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "sanitizers": {"type": "string",
                                "default": "asan,ubsan"},
                "timeout_seconds": {"type": "integer", "default": 1800},
            },
            "required": ["repo"],
        }),

        # ─── v3: Layer 4 patch infrastructure ────────────────────────────
        Tool(name="patch_essence", description=(
            "Given a git commit SHA in a repo, extract the bug-class "
            "abstraction: files changed, removed dangerous patterns, added "
            "safety guards, and a semgrep-style rule that matches the "
            "BEFORE state. Output suitable for propagate_pattern. The "
            "rule lives in the patch_rules KG table."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "commit_sha": {"type": "string"},
            },
            "required": ["repo", "commit_sha"],
        }),

        Tool(name="propagate_pattern", description=(
            "Run a previously-generated rule (from patch_essence or a "
            "confirmed finding) across the codebase to find variants of "
            "the same bug class. Returns matching file:line sites. "
            "Variants become child hypotheses for the validator."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "rule_yaml": {"type": "string"},
                "rule_id": {"type": "string"},
            },
            "required": ["repo"],
        }),

        Tool(name="fetch_payload", description=(
            "Retrieve a large tool payload from the off-context cache by handle. "
            "Use after seeing a payload_ref in a previous tool result."
        ), inputSchema={
            "type": "object",
            "properties": {
                "payload_ref": {"type": "string"},
                "page": {"type": "integer", "default": 0},
                "page_size_bytes": {"type": "integer", "default": 32000},
            },
            "required": ["payload_ref"],
        }),
    ]


# ─── tool implementations ───────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "app_inventory":
            return _tool_app_inventory()
        if name == "file_tree":
            return _tool_file_tree(arguments)
        if name == "language_stats":
            return _tool_language_stats(arguments)
        if name == "dependency_graph":
            return _tool_dependency_graph(arguments)
        if name == "dependency_vulns":
            return _tool_dependency_vulns(arguments)
        if name == "secret_scan":
            return _tool_secret_scan(arguments)
        if name == "iac_scan":
            return _tool_iac_scan(arguments)
        if name == "entrypoints":
            return _tool_entrypoints(arguments)
        if name == "api_surface":
            return _tool_api_surface(arguments)
        if name == "auth_surface":
            return _tool_auth_surface(arguments)
        if name == "authz_checks":
            return _tool_authz_checks(arguments)
        if name == "data_sources":
            return _tool_data_sources(arguments)
        if name == "data_sinks":
            return _tool_data_sinks(arguments)
        if name == "taint_paths":
            return _tool_taint_paths(arguments)
        if name == "cross_repo_calls":
            return _tool_cross_repo_calls()
        if name == "service_map":
            return _tool_service_map()
        if name == "db_schema":
            return _tool_db_schema(arguments)
        if name == "git_hotspots":
            return _tool_git_hotspots(arguments)
        if name == "framework_detect":
            return _tool_framework_detect(arguments)
        if name == "crypto_usage":
            return _tool_semgrep_pattern(arguments, "crypto")
        if name == "serialize_calls":
            return _tool_semgrep_pattern(arguments, "serialize")
        if name == "template_engines":
            return _tool_semgrep_pattern(arguments, "template")
        if name == "regex_audit":
            return _tool_semgrep_pattern(arguments, "regex")
        if name == "code_excerpt":
            return _tool_code_excerpt(arguments)
        if name == "ast_query":
            return _tool_ast_query(arguments)
        if name == "git_blame_function":
            return _tool_git_blame_function(arguments)
        if name == "recent_security_commits":
            return _tool_recent_security_commits(arguments)
        if name == "function_change_history":
            return _tool_function_change_history(arguments)
        if name == "removed_code_in_last_n_days":
            return _tool_removed_code_in_last_n_days(arguments)
        if name == "commit_message_search":
            return _tool_commit_message_search(arguments)
        if name == "data_flow_paths":
            return _tool_data_flow_paths(arguments)
        if name == "reachable_from":
            return _tool_reachable_from(arguments)
        if name == "callers_of":
            return _tool_callers_of(arguments)
        if name == "callees_of":
            return _tool_callees_of(arguments)
        if name == "custom_semgrep_scan":
            return _tool_custom_semgrep_scan(arguments)
        if name == "test_coverage_for_endpoint":
            return _tool_test_coverage_for_endpoint(arguments)
        if name == "test_assertions_for_function":
            return _tool_test_assertions_for_function(arguments)
        if name == "untested_handlers":
            return _tool_untested_handlers(arguments)
        if name == "state_machine_extract":
            return _tool_state_machine_extract(arguments)
        if name == "known_gadgets":
            return _tool_known_gadgets(arguments)
        if name == "trust_shadow_analyze":
            return _tool_trust_shadow_analyze()
        # ─── v3 Layer 2 ──
        if name == "integer_range_analysis":
            return _tool_integer_range_analysis(arguments)
        if name == "lifetime_analysis":
            return _tool_lifetime_analysis(arguments)
        if name == "format_string_sinks":
            return _tool_format_string_sinks(arguments)
        if name == "type_confusion_sites":
            return _tool_type_confusion_sites(arguments)
        if name == "allocator_map":
            return _tool_allocator_map(arguments)
        # ─── v3 Layer 3 ──
        if name == "sanitizer_build":
            return _tool_sanitizer_build(arguments)
        # ─── v3 Layer 4 ──
        if name == "patch_essence":
            return _tool_patch_essence(arguments)
        if name == "propagate_pattern":
            return _tool_propagate_pattern(arguments)
        if name == "fetch_payload":
            return _tool_fetch_payload(arguments)
    except Exception as e:
        return _err(f"tool '{name}' raised: {e}")
    return _err(f"unknown tool: {name}")


def _tool_app_inventory() -> list[TextContent]:
    manifest = _load_manifest()
    repos = _repo_paths()
    rows = []
    for name, path in repos.items():
        files = _iter_files(path, max_files=5000)
        loc_by_lang: Counter[str] = Counter()
        for f in files:
            lang = LANG_EXT.get(f.suffix.lower())
            if not lang:
                continue
            try:
                loc_by_lang[lang] += sum(1 for _ in f.open("rb"))
            except OSError:
                pass
        rows.append({
            "name": name,
            "path": str(path),
            "files": len(files),
            "loc_by_lang": dict(loc_by_lang.most_common()),
        })
    summary = (
        f"{len(rows)} repos: " +
        ", ".join(f"{r['name']} ({r['files']} files)" for r in rows)
    )
    return _ok({
        "summary": summary,
        "manifest": manifest.get("application", {}),
        "trust_boundaries": manifest.get("trust_boundaries", []),
        "handles": rows,
    })


def _tool_file_tree(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    max_depth = args.get("max_depth", 6)
    max_files = args.get("max_files", 500)
    inc = re.compile(args["include"]) if args.get("include") else None
    exc = re.compile(args["exclude"]) if args.get("exclude") else None

    items = []
    for p in _iter_files(root, max_files=10000):
        rel = p.relative_to(root)
        if len(rel.parts) > max_depth:
            continue
        if inc and not inc.search(str(rel)):
            continue
        if exc and exc.search(str(rel)):
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        items.append({"path": str(rel), "size": size})
        if len(items) >= max_files:
            break
    return _ok({
        "summary": f"{len(items)} files in {repo_name}",
        "handles": items,
    })


def _tool_language_stats(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    files_by_lang: Counter[str] = Counter()
    loc_by_lang: Counter[str] = Counter()
    for f in _iter_files(root):
        lang = LANG_EXT.get(f.suffix.lower())
        if not lang:
            continue
        files_by_lang[lang] += 1
        try:
            loc_by_lang[lang] += sum(1 for _ in f.open("rb"))
        except OSError:
            pass
    return _ok({
        "summary": f"top languages: " + ", ".join(
            f"{l}({c})" for l, c in loc_by_lang.most_common(5)
        ),
        "facets": {
            "files_by_lang": dict(files_by_lang),
            "loc_by_lang": dict(loc_by_lang),
        },
    })


def _tool_dependency_graph(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    deps: list[dict] = []

    # package.json
    for pj in root.rglob("package.json"):
        if SKIP_PATTERNS.search(str(pj)):
            continue
        try:
            doc = json.loads(pj.read_text())
        except Exception:
            continue
        for k, v in (doc.get("dependencies") or {}).items():
            deps.append({"manifest": str(pj.relative_to(root)),
                         "ecosystem": "npm", "name": k, "version": v, "scope": "runtime"})
        for k, v in (doc.get("devDependencies") or {}).items():
            deps.append({"manifest": str(pj.relative_to(root)),
                         "ecosystem": "npm", "name": k, "version": v, "scope": "dev"})

    # requirements.txt / requirements*.txt
    for rt in list(root.rglob("requirements*.txt")):
        if SKIP_PATTERNS.search(str(rt)):
            continue
        try:
            for line in rt.read_text().splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]=?.*)?$", line)
                if m:
                    deps.append({"manifest": str(rt.relative_to(root)),
                                 "ecosystem": "pypi", "name": m.group(1),
                                 "version": (m.group(2) or "").strip(),
                                 "scope": "runtime"})
        except OSError:
            pass

    # go.mod
    for gm in root.rglob("go.mod"):
        if SKIP_PATTERNS.search(str(gm)):
            continue
        try:
            for line in gm.read_text().splitlines():
                m = re.match(r"^\s*(?:require\s+)?([^\s]+)\s+(v[\w.\-+]+)", line)
                if m and "/" in m.group(1):
                    deps.append({"manifest": str(gm.relative_to(root)),
                                 "ecosystem": "go", "name": m.group(1),
                                 "version": m.group(2), "scope": "runtime"})
        except OSError:
            pass

    # pom.xml (lightweight regex parse — sufficient as a recon signal)
    for pm in root.rglob("pom.xml"):
        if SKIP_PATTERNS.search(str(pm)):
            continue
        try:
            text = pm.read_text()
        except OSError:
            continue
        for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            text, re.DOTALL
        ):
            deps.append({"manifest": str(pm.relative_to(root)),
                         "ecosystem": "maven",
                         "name": f"{m.group(1)}:{m.group(2)}",
                         "version": m.group(3), "scope": "runtime"})

    # Gemfile (very lightweight)
    for gf in root.rglob("Gemfile"):
        if SKIP_PATTERNS.search(str(gf)):
            continue
        try:
            for line in gf.read_text().splitlines():
                m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                if m:
                    deps.append({"manifest": str(gf.relative_to(root)),
                                 "ecosystem": "rubygems", "name": m.group(1),
                                 "version": m.group(2) or "", "scope": "runtime"})
        except OSError:
            pass

    # Cargo.toml
    for ct in root.rglob("Cargo.toml"):
        if SKIP_PATTERNS.search(str(ct)):
            continue
        try:
            text = ct.read_text()
        except OSError:
            continue
        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and not stripped.startswith("[dependencies."):
                in_deps = False
            if in_deps:
                m = re.match(r"([\w\-]+)\s*=\s*[\"']([^\"']+)[\"']", stripped)
                if m:
                    deps.append({"manifest": str(ct.relative_to(root)),
                                 "ecosystem": "cargo", "name": m.group(1),
                                 "version": m.group(2), "scope": "runtime"})

    ecosystems = Counter(d["ecosystem"] for d in deps)
    return _ok({
        "summary": f"{len(deps)} dependencies across {len(ecosystems)} ecosystems: " +
                   ", ".join(f"{e}({c})" for e, c in ecosystems.most_common()),
        "facets": {"by_ecosystem": dict(ecosystems)},
        "handles": deps[:200],
        "payload_ref": _stash_payload(f"deps-{repo_name}", deps) if len(deps) > 200 else None,
    })


def _tool_dependency_vulns(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]

    rc, out, err = _run(
        ["osv-scanner", "--format=json", "--recursive", str(root)],
        timeout=600,
    )
    if rc not in (0, 1):  # 1 means vulns found
        return _err(f"osv-scanner failed: {err.strip()[:300]}")
    try:
        report = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        report = {}
    vulns: list[dict] = []
    for res in report.get("results", []) or []:
        for pkg in res.get("packages", []) or []:
            pinfo = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []) or []:
                vulns.append({
                    "id": v.get("id"),
                    "package": pinfo.get("name"),
                    "ecosystem": pinfo.get("ecosystem"),
                    "version": pinfo.get("version"),
                    "summary": (v.get("summary") or "")[:200],
                    "severity": (v.get("database_specific", {}) or {}).get("severity"),
                })
    by_sev = Counter(v.get("severity") or "unknown" for v in vulns)
    return _ok({
        "summary": f"{len(vulns)} vulnerabilities found",
        "facets": {"by_severity": dict(by_sev)},
        "handles": vulns[:100],
        "payload_ref": _stash_payload(f"vulns-{repo_name}", vulns) if len(vulns) > 100 else None,
    })


def _tool_secret_scan(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    out_path = TOOL_CACHE / f"gitleaks-{repo_name}.json"
    rc, _, err = _run(
        ["gitleaks", "detect", "--source", str(root),
         "--report-format", "json", "--report-path", str(out_path),
         "--no-git", "--exit-code", "0"],
        timeout=600,
    )
    if rc not in (0, 1):
        return _err(f"gitleaks failed: {err.strip()[:300]}")
    findings: list[dict] = []
    if out_path.exists():
        try:
            findings = json.loads(out_path.read_text() or "[]")
        except json.JSONDecodeError:
            findings = []
    handles = [
        {"rule": f.get("RuleID"), "file": f.get("File"),
         "line": f.get("StartLine"), "fingerprint": f.get("Fingerprint")}
        for f in findings
    ]
    return _ok({
        "summary": f"{len(findings)} secret candidates",
        "handles": handles[:100],
        "payload_ref": _stash_payload(f"secrets-{repo_name}", findings) if len(findings) > 100 else None,
    })


def _tool_iac_scan(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    rc, out, err = _run(
        ["trivy", "config", "--format", "json", str(root)],
        timeout=600,
    )
    if rc != 0:
        return _err(f"trivy config failed: {err.strip()[:300]}")
    try:
        report = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        report = {}
    misconfigs: list[dict] = []
    for res in report.get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            misconfigs.append({
                "id": m.get("ID"),
                "type": m.get("Type"),
                "title": m.get("Title"),
                "severity": m.get("Severity"),
                "file": res.get("Target"),
                "message": (m.get("Message") or "")[:200],
            })
    by_sev = Counter(m.get("severity", "UNKNOWN") for m in misconfigs)
    return _ok({
        "summary": f"{len(misconfigs)} misconfigurations",
        "facets": {"by_severity": dict(by_sev)},
        "handles": misconfigs[:100],
        "payload_ref": _stash_payload(f"iac-{repo_name}", misconfigs) if len(misconfigs) > 100 else None,
    })


# ── Framework-aware entrypoint detection (pattern-driven) ──────────────────

ENTRYPOINT_PATTERNS = {
    "python-flask":   re.compile(r"@\w+\.route\(['\"]([^'\"]+)['\"]"),
    "python-fastapi": re.compile(r"@\w+\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"),
    "python-django":  re.compile(r"^\s*path\(\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
    "js-express":     re.compile(r"\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"),
    "js-nextjs-app":  re.compile(r"export\s+(default\s+)?async\s+function\s+(GET|POST|PUT|DELETE|PATCH)"),
    "go-gin":         re.compile(r"\.(GET|POST|PUT|DELETE|PATCH)\(\s*['\"]([^'\"]+)['\"]"),
    "go-chi":         re.compile(r"r\.(Get|Post|Put|Delete|Patch)\(\s*['\"]([^'\"]+)['\"]"),
    "java-spring":    re.compile(
        r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)"
        r"\([^)]*['\"]([^'\"]+)['\"]"
    ),
    "ruby-rails":     re.compile(r"^\s*(get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
}


def _tool_entrypoints(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    handles: list[dict] = []
    for f in _iter_files(root):
        if f.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx",
                                      ".go", ".java", ".rb"}:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for framework, pat in ENTRYPOINT_PATTERNS.items():
            for m in pat.finditer(text):
                groups = m.groups()
                path = groups[-1]
                line_no = text.count("\n", 0, m.start()) + 1
                handles.append({
                    "framework": framework, "path": path,
                    "file": str(f.relative_to(root)), "line": line_no,
                })
    by_fw = Counter(h["framework"] for h in handles)
    return _ok({
        "summary": f"{len(handles)} entrypoints across {len(by_fw)} frameworks",
        "facets": {"by_framework": dict(by_fw)},
        "handles": handles[:300],
        "payload_ref": _stash_payload(f"entrypoints-{repo_name}", handles) if len(handles) > 300 else None,
    })


def _tool_api_surface(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    specs: list[dict] = []
    for f in root.rglob("*"):
        if SKIP_PATTERNS.search(str(f)) or not f.is_file():
            continue
        name = f.name.lower()
        if name in {"openapi.yaml", "openapi.yml", "openapi.json",
                     "swagger.yaml", "swagger.yml", "swagger.json"} or \
           name.endswith(".proto") or name.endswith(".graphql"):
            specs.append({"path": str(f.relative_to(root)), "kind": name.split(".")[-1]})
    return _ok({
        "summary": f"{len(specs)} API specifications detected",
        "handles": specs,
    })


AUTH_HINT = re.compile(
    r"(jwt|bearer|session\b|@login_required|requires_auth|"
    r"authenticate|verify_token|passport|oauth|saml)",
    re.IGNORECASE,
)


def _tool_auth_surface(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    hits: list[dict] = []
    for f in _iter_files(root):
        if f.suffix.lower() not in {".py", ".js", ".ts", ".go", ".java", ".rb"}:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for m in AUTH_HINT.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            hits.append({"keyword": m.group(0),
                          "file": str(f.relative_to(root)), "line": line_no})
            if len(hits) >= 400:
                break
    return _ok({
        "summary": f"{len(hits)} auth-related sites",
        "handles": hits[:200],
        "payload_ref": _stash_payload(f"auth-{repo_name}", hits) if len(hits) > 200 else None,
    })


AUTHZ_HINT = re.compile(
    r"(is_admin|has_role|hasPermission|authorize|@PreAuthorize|"
    r"@RolesAllowed|can\?|isOwner|owner_id\s*==|access_denied)",
    re.IGNORECASE,
)


def _tool_authz_checks(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    hits: list[dict] = []
    for f in _iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for m in AUTHZ_HINT.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            hits.append({"keyword": m.group(0),
                          "file": str(f.relative_to(root)), "line": line_no})
    return _ok({
        "summary": f"{len(hits)} authorization-check sites",
        "handles": hits[:200],
        "payload_ref": _stash_payload(f"authz-{repo_name}", hits) if len(hits) > 200 else None,
    })


SOURCE_PATTERNS = {
    "python": [
        r"request\.(args|form|json|data|files|headers|cookies)",
        r"flask\.request\.",
        r"input\(",
    ],
    "javascript": [r"req\.(body|query|params|headers|cookies)"],
    "go":         [r"r\.(URL\.Query|FormValue|PostFormValue|Header\.Get)"],
}
SINK_PATTERNS = {
    "exec":     [r"\bsubprocess\.(run|call|Popen|check_output)", r"\bos\.system",
                  r"\bchild_process\.exec", r"\bRuntime\.getRuntime\(\)\.exec"],
    "sql":      [r"\.execute\(['\"][^'\"]*\$\{", r"f['\"].*SELECT", r"f['\"].*INSERT",
                  r"f['\"].*UPDATE", r"f['\"].*DELETE"],
    "http":     [r"requests\.(get|post|put|delete)\(", r"axios\.",
                  r"http\.NewRequest", r"fetch\("],
    "fs_write": [r"\bopen\(\s*['\"][^'\"]+['\"],\s*['\"][wa]",
                  r"\bfs\.write(File|FileSync)"],
    "eval":     [r"\beval\(", r"\bnew Function\(", r"\bexec\("],
}


def _tool_data_sources(args: dict) -> list[TextContent]:
    return _scan_patterns(args, SOURCE_PATTERNS, label="source")


def _tool_data_sinks(args: dict) -> list[TextContent]:
    flat = {f"sink:{k}": v for k, vs in SINK_PATTERNS.items() for v in [vs]}
    flat_single: dict[str, list[str]] = {}
    for k, vs in SINK_PATTERNS.items():
        flat_single[f"sink:{k}"] = vs
    return _scan_patterns(args, flat_single, label="sink")


def _scan_patterns(args: dict, patterns: dict[str, list[str]], label: str) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    compiled = {
        k: [re.compile(p) for p in v]
        for k, v in patterns.items()
    }
    hits: list[dict] = []
    for f in _iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for kind, pats in compiled.items():
            for pat in pats:
                for m in pat.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    hits.append({
                        "kind": kind, "match": m.group(0)[:80],
                        "file": str(f.relative_to(root)), "line": line_no,
                    })
                    if len(hits) >= 1500:
                        break
    by_kind = Counter(h["kind"] for h in hits)
    return _ok({
        "summary": f"{len(hits)} {label} sites across {len(by_kind)} kinds",
        "facets": {"by_kind": dict(by_kind)},
        "handles": hits[:300],
        "payload_ref": _stash_payload(f"{label}-{repo_name}", hits) if len(hits) > 300 else None,
    })


def _tool_taint_paths(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    # Use semgrep's built-in security ruleset as a baseline taint signal.
    rc, out, err = _run(
        ["semgrep", "--config", "auto", "--json",
         "--timeout", "120", "--metrics", "off", str(root)],
        timeout=900,
    )
    if rc not in (0, 1):
        return _err(f"semgrep failed: {err.strip()[:300]}")
    try:
        report = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        report = {}
    results = report.get("results", []) or []
    handles = [
        {
            "rule": r.get("check_id"),
            "severity": (r.get("extra", {}) or {}).get("severity"),
            "file": r.get("path"),
            "line": (r.get("start", {}) or {}).get("line"),
            "message": ((r.get("extra", {}) or {}).get("message") or "")[:200],
        }
        for r in results
    ]
    by_sev = Counter(h.get("severity") or "INFO" for h in handles)
    return _ok({
        "summary": f"{len(handles)} semgrep taint hits",
        "facets": {"by_severity": dict(by_sev)},
        "handles": handles[:200],
        "payload_ref": _stash_payload(f"semgrep-{repo_name}", handles) if len(handles) > 200 else None,
    })


CROSS_REPO_CALL_PATTERNS = [
    re.compile(r"https?://([\w.-]+\.internal|\w+-svc|\w+-api|\w+\.svc\.cluster)"),
    re.compile(r"http://([\w.-]+):\d+"),
]


def _tool_cross_repo_calls() -> list[TextContent]:
    manifest = _load_manifest()
    repos = _repo_paths()
    repo_names = list(repos.keys())
    hits: list[dict] = []
    for repo_name, root in repos.items():
        for f in _iter_files(root):
            if f.suffix.lower() not in {".py", ".js", ".ts", ".go",
                                          ".java", ".rb", ".yaml", ".yml"}:
                continue
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            for other in repo_names:
                if other == repo_name:
                    continue
                # Look for any reference to the other repo's name as a host hint
                if other.lower() in text.lower():
                    for m in re.finditer(
                        rf"(?i)https?://[^\"'\s]*{re.escape(other)}[^\"'\s]*", text
                    ):
                        line_no = text.count("\n", 0, m.start()) + 1
                        hits.append({
                            "from_repo": repo_name, "to_repo": other,
                            "file": str(f.relative_to(root)),
                            "line": line_no, "url_hint": m.group(0)[:120],
                        })
    by_edge = Counter((h["from_repo"], h["to_repo"]) for h in hits)
    return _ok({
        "summary": f"{len(hits)} cross-repo call sites; "
                    f"{len(by_edge)} unique edges",
        "facets": {"edges": [
            {"from": k[0], "to": k[1], "count": v} for k, v in by_edge.items()
        ]},
        "handles": hits[:200],
        "trust_boundaries": manifest.get("trust_boundaries", []),
    })


def _tool_service_map() -> list[TextContent]:
    manifest = _load_manifest()
    repos = manifest.get("repos", []) or []
    edges_payload = json.loads(_tool_cross_repo_calls()[0].text)
    return _ok({
        "summary": f"Service map: {len(repos)} services, "
                    f"{len(edges_payload.get('facets', {}).get('edges', []))} edges",
        "nodes": [
            {"name": r.get("name"), "role": r.get("role"),
             "runtime": r.get("runtime"), "exposes": r.get("exposes", [])}
            for r in repos
        ],
        "edges": edges_payload.get("facets", {}).get("edges", []),
        "trust_boundaries": manifest.get("trust_boundaries", []),
    })


def _tool_db_schema(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    tables: list[dict] = []
    # CREATE TABLE statements anywhere
    for f in root.rglob("*"):
        if not f.is_file() or SKIP_PATTERNS.search(str(f)):
            continue
        if f.suffix.lower() not in {".sql", ".py", ".rb", ".js", ".ts", ".go"}:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for m in re.finditer(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`]?(\w+)[\"`]?",
            text, re.IGNORECASE,
        ):
            line_no = text.count("\n", 0, m.start()) + 1
            tables.append({"table": m.group(1),
                            "file": str(f.relative_to(root)), "line": line_no})
    return _ok({
        "summary": f"{len(tables)} tables detected via CREATE TABLE",
        "handles": tables[:200],
    })


def _tool_git_hotspots(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    days = args.get("days", 180)
    top_n = args.get("top_n", 30)
    rc, out, err = _run(
        ["git", "-C", str(root), "log", f"--since={days}.days.ago",
         "--name-only", "--pretty=format:"],
        timeout=120,
    )
    if rc != 0:
        return _err(f"git log failed: {err.strip()[:200]}")
    counts: Counter[str] = Counter()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        counts[line] += 1
    hot = counts.most_common(top_n)
    return _ok({
        "summary": f"top {len(hot)} hotspot files (last {days}d)",
        "handles": [{"file": f, "changes": c} for f, c in hot],
    })


FRAMEWORK_SIGNS = {
    "fastapi":    [r"from\s+fastapi\b", r"FastAPI\("],
    "flask":      [r"from\s+flask\b", r"Flask\("],
    "django":     [r"from\s+django", r"INSTALLED_APPS"],
    "express":    [r"require\(['\"]express['\"]", r"from\s+['\"]express['\"]"],
    "nextjs":     [r"['\"]next['\"]", r"export\s+default\s+function\s+Page"],
    "spring":     [r"@SpringBootApplication", r"@RestController"],
    "rails":      [r"Rails::Application", r"class\s+\w+\s*<\s*ApplicationController"],
    "gin":        [r"github.com/gin-gonic/gin"],
    "chi":        [r"github.com/go-chi/chi"],
}
FRAMEWORK_FOOTGUNS = {
    "fastapi": "Default response is HTML for HTMLResponse — XSS via reflected params.",
    "flask":   "render_template_string with user input → SSTI.",
    "django":  "`mark_safe` and `safe` filter strip auto-escaping.",
    "express": "express.json() with strict:false accepts JS values; cookie-parser is often missing signing.",
    "nextjs":  "API route handlers default to permissive CORS unless configured.",
    "spring":  "@RequestParam without binding annotations may accept unexpected types; SpEL injection via @Value.",
    "rails":   "Strong Parameters bypass through nested attrs; mass-assignment in older code.",
    "gin":     "BindJSON/ShouldBindJSON do not enforce required fields by default.",
    "chi":     "URL params are unvalidated by default.",
}


def _tool_framework_detect(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    detected: dict[str, int] = {}
    for f in _iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for fw, pats in FRAMEWORK_SIGNS.items():
            for p in pats:
                if re.search(p, text):
                    detected[fw] = detected.get(fw, 0) + 1
                    break
    out = [{"framework": fw, "hits": n,
            "well_known_footguns": FRAMEWORK_FOOTGUNS.get(fw)}
           for fw, n in sorted(detected.items(), key=lambda x: -x[1])]
    return _ok({
        "summary": f"{len(out)} frameworks detected",
        "handles": out,
    })


SEMGREP_INLINE_RULESETS = {
    "crypto": "p/crypto",
    "serialize": "p/insecure-deserialization",
    "template": "p/owasp-top-ten",
    "regex": "r/generic.secrets",
}


def _tool_semgrep_pattern(args: dict, kind: str) -> list[TextContent]:
    """Family of pattern-based scans run via semgrep registry rulesets."""
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    ruleset = SEMGREP_INLINE_RULESETS.get(kind, "auto")
    rc, out, err = _run(
        ["semgrep", "--config", ruleset, "--json",
         "--timeout", "60", "--metrics", "off", str(root)],
        timeout=600,
    )
    if rc not in (0, 1):
        return _err(f"semgrep ({kind}) failed: {err.strip()[:300]}")
    try:
        report = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        report = {}
    hits = [{
        "rule": r.get("check_id"),
        "file": r.get("path"),
        "line": (r.get("start", {}) or {}).get("line"),
        "message": ((r.get("extra", {}) or {}).get("message") or "")[:200],
    } for r in (report.get("results", []) or [])]
    return _ok({
        "summary": f"{len(hits)} {kind} hits",
        "handles": hits[:200],
        "payload_ref": _stash_payload(f"{kind}-{repo_name}", hits) if len(hits) > 200 else None,
    })


def _tool_code_excerpt(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    file_rel = args["file"]
    line = int(args["line"])
    ctx = int(args.get("context_lines", 30))
    fpath = (root / file_rel).resolve()
    if not str(fpath).startswith(str(root.resolve())):
        return _err("path escape")
    if not fpath.exists():
        return _err(f"file not found: {file_rel}")
    try:
        lines = fpath.read_text(errors="ignore").splitlines()
    except OSError as e:
        return _err(f"read failed: {e}")
    start = max(0, line - ctx - 1)
    end = min(len(lines), line + ctx)
    excerpt = "\n".join(
        f"{i + 1:>5}{'>' if i + 1 == line else ' '} {l}"
        for i, l in enumerate(lines[start:end], start=start)
    )
    return _ok({
        "summary": f"{file_rel}:{line} (±{ctx} lines)",
        "excerpt": excerpt,
    })


def _tool_ast_query(args: dict) -> list[TextContent]:
    repo_name = args["repo"]
    repos = _repo_paths()
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    try:
        from tree_sitter_languages import get_language, get_parser
    except ImportError:
        return _err("tree-sitter-languages not installed")
    try:
        lang = get_language(args["language"])
        parser = get_parser(args["language"])
    except Exception as e:
        return _err(f"language not supported: {e}")
    root = repos[repo_name]
    query = lang.query(args["query"])
    max_results = args.get("max_results", 50)
    suffix_for_lang = {
        "python": [".py"], "javascript": [".js", ".jsx", ".mjs"],
        "typescript": [".ts", ".tsx"], "go": [".go"], "java": [".java"],
        "ruby": [".rb"], "rust": [".rs"], "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".hpp"], "php": [".php"], "c_sharp": [".cs"],
    }.get(args["language"], [])
    hits: list[dict] = []
    for f in _iter_files(root):
        if suffix_for_lang and f.suffix.lower() not in suffix_for_lang:
            continue
        try:
            src = f.read_bytes()
        except OSError:
            continue
        tree = parser.parse(src)
        for node, name in query.captures(tree.root_node):
            hits.append({
                "file": str(f.relative_to(root)),
                "line": node.start_point[0] + 1,
                "capture": name,
                "text": src[node.start_byte:node.end_byte][:200].decode(errors="replace"),
            })
            if len(hits) >= max_results:
                break
        if len(hits) >= max_results:
            break
    return _ok({"summary": f"{len(hits)} matches", "handles": hits})


# ─── new in v2: git history tools ───────────────────────────────────────────

def _tool_git_blame_function(args: dict) -> list[TextContent]:
    from lacuna.tools.git_history import git_blame_function
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(git_blame_function(
        repos[args["repo"]], args["file"],
        int(args["line_start"]), int(args["line_end"]),
    ))


def _tool_recent_security_commits(args: dict) -> list[TextContent]:
    from lacuna.tools.git_history import recent_security_commits
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(recent_security_commits(
        repos[args["repo"]],
        int(args.get("days", 365)), int(args.get("limit", 50)),
    ))


def _tool_function_change_history(args: dict) -> list[TextContent]:
    from lacuna.tools.git_history import function_change_history
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(function_change_history(
        repos[args["repo"]], args["file"], int(args["line"]),
        int(args.get("context_lines", 30)),
    ))


def _tool_removed_code_in_last_n_days(args: dict) -> list[TextContent]:
    from lacuna.tools.git_history import removed_code_in_last_n_days
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(removed_code_in_last_n_days(
        repos[args["repo"]],
        int(args.get("days", 90)), int(args.get("limit", 100)),
    ))


def _tool_commit_message_search(args: dict) -> list[TextContent]:
    from lacuna.tools.git_history import commit_message_search
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(commit_message_search(
        repos[args["repo"]], args["pattern"],
        int(args.get("limit", 50)),
    ))


# ─── new in v2: data-flow engine (CodeQL-equivalent) ────────────────────────

# Per-repo call graph cache. Built once per scan; cleared when this process
# restarts. Building a graph costs seconds for medium repos; reusing it costs
# microseconds.
_CG_CACHE: dict[str, Any] = {}


def _get_call_graph(repo_name: str):
    from lacuna.flow import build_call_graph
    if repo_name in _CG_CACHE:
        return _CG_CACHE[repo_name]
    repos = _repo_paths()
    if repo_name not in repos:
        return None
    cg = build_call_graph(repos[repo_name])
    _CG_CACHE[repo_name] = cg
    return cg


def _tool_data_flow_paths(args: dict) -> list[TextContent]:
    from lacuna.flow import taint_paths
    from lacuna.kg import FlowPath, open_kg
    repo = args["repo"]
    cg = _get_call_graph(repo)
    if cg is None:
        return _err(f"unknown repo: {repo}")
    src_kind = args.get("source_kind")
    sink_kind = args.get("sink_kind")
    max_depth = int(args.get("max_depth", 6))
    hits = taint_paths(cg, max_depth=max_depth)
    if src_kind:
        hits = [h for h in hits if h.source_kind == src_kind]
    if sink_kind:
        hits = [h for h in hits if h.sink_kind == sink_kind]
    # Persist to KG
    try:
        kg = open_kg()
        for h in hits[:200]:
            fp = FlowPath(
                repo=repo, source_kind=h.source_kind, sink_kind=h.sink_kind,
                path=h.path, sanitizers_crossed=h.sanitizers_crossed,
                confidence=h.confidence,
            )
            kg.add_flow_path(fp)
        kg.close()
    except Exception:
        pass
    handles = [{
        "source_kind": h.source_kind, "sink_kind": h.sink_kind,
        "function": h.function,
        "file": h.file, "line": h.line,
        "sink_call": h.sink_call_repr,
        "confidence": h.confidence,
        "path_steps": len(h.path),
        "path_preview": h.path[:8],
    } for h in hits[:200]]
    payload_ref = None
    if len(hits) > 200:
        payload_ref = _stash_payload(f"dataflow-{repo}", {
            "all_hits": [
                {
                    "source_kind": h.source_kind, "sink_kind": h.sink_kind,
                    "function": h.function, "file": h.file, "line": h.line,
                    "sink_call": h.sink_call_repr, "confidence": h.confidence,
                    "path": h.path,
                }
                for h in hits
            ]
        })
    return _ok({
        "summary": f"{len(hits)} taint paths found"
                    + (f" (returning first 200; full set via payload_ref)" if payload_ref else ""),
        "handles": handles,
        "payload_ref": payload_ref,
        "facets": {
            "by_sink_kind": dict(Counter(h.sink_kind for h in hits)),
            "by_source_kind": dict(Counter(h.source_kind for h in hits)),
        },
    })


def _tool_reachable_from(args: dict) -> list[TextContent]:
    from lacuna.flow import reachable
    from lacuna.kg import open_kg
    repo = args["repo"]
    cg = _get_call_graph(repo)
    if cg is None:
        return _err(f"unknown repo: {repo}")
    src = args["source_function"]
    tgt = args["target_function"]
    max_depth = int(args.get("max_depth", 8))
    ok, path = reachable(cg, src, tgt, max_depth=max_depth)
    # Cache to KG
    try:
        kg = open_kg()
        kg.cache_reachability(repo, src, tgt, ok, path)
        kg.close()
    except Exception:
        pass
    return _ok({
        "summary": f"reachable={ok} from {src} to {tgt}"
                    + (f" via {len(path)} hops" if ok else ""),
        "reachable": ok,
        "path": path,
    })


def _tool_callers_of(args: dict) -> list[TextContent]:
    from lacuna.flow import callers
    repo = args["repo"]
    cg = _get_call_graph(repo)
    if cg is None:
        return _err(f"unknown repo: {repo}")
    transitive = bool(args.get("transitive", True))
    cs = callers(cg, args["function"], transitive=transitive)
    return _ok({
        "summary": f"{len(cs)} callers of {args['function']}"
                    + (" (transitive)" if transitive else ""),
        "handles": sorted(cs)[:500],
    })


def _tool_callees_of(args: dict) -> list[TextContent]:
    repo = args["repo"]
    cg = _get_call_graph(repo)
    if cg is None:
        return _err(f"unknown repo: {repo}")
    transitive = bool(args.get("transitive", True))
    cs = cg.callees(args["function"], transitive=transitive)
    return _ok({
        "summary": f"{len(cs)} callees of {args['function']}"
                    + (" (transitive)" if transitive else ""),
        "handles": sorted(cs)[:500],
    })


# ─── new in v2: custom semgrep ─────────────────────────────────────────────

def _tool_custom_semgrep_scan(args: dict) -> list[TextContent]:
    from lacuna.tools.custom_semgrep import build_ruleset, run_custom_semgrep
    repos = _repo_paths()
    repo_name = args["repo"]
    if repo_name not in repos:
        return _err(f"unknown repo: {repo_name}")
    root = repos[repo_name]
    # Reuse framework_detect and language_stats outputs to drive ruleset
    fw_text = _tool_framework_detect({"repo": repo_name})
    lang_text = _tool_language_stats({"repo": repo_name})
    try:
        fw = json.loads(fw_text[0].text)
        langs = json.loads(lang_text[0].text)
    except Exception:
        fw, langs = {}, {}
    detected_frameworks = [
        f["framework"] for f in (fw.get("handles") or [])
    ] if isinstance(fw, dict) else []
    detected_languages = [
        l.get("language", "").lower()
        for l in (langs.get("handles") or [])
    ] if isinstance(langs, dict) else []
    ruleset = build_ruleset(root, detected_frameworks, detected_languages)
    return _ok(run_custom_semgrep(root, ruleset))


# ─── new in v2: test coverage oracle ────────────────────────────────────────

def _tool_test_coverage_for_endpoint(args: dict) -> list[TextContent]:
    from lacuna.tools.test_coverage import test_coverage_for_endpoint
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(test_coverage_for_endpoint(repos[args["repo"]], args["route"]))


def _tool_test_assertions_for_function(args: dict) -> list[TextContent]:
    from lacuna.tools.test_coverage import test_assertions_for_function
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(test_assertions_for_function(
        repos[args["repo"]], args["function"],
    ))


def _tool_untested_handlers(args: dict) -> list[TextContent]:
    from lacuna.tools.test_coverage import untested_handlers
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(untested_handlers(
        repos[args["repo"]], args.get("routes", []) or [],
    ))


# ─── new in v2: state machine extraction ───────────────────────────────────

def _tool_state_machine_extract(args: dict) -> list[TextContent]:
    from lacuna.tools.state_machine import extract_state_machine
    repos = _repo_paths()
    if args["repo"] not in repos:
        return _err(f"unknown repo: {args['repo']}")
    return _ok(extract_state_machine(repos[args["repo"]]))


# ─── new in v2: gadget catalog ─────────────────────────────────────────────

def _tool_known_gadgets(args: dict) -> list[TextContent]:
    from lacuna.kg import open_kg
    kg = open_kg()
    try:
        rows = kg.query_gadgets(args["language"], args.get("library"))
        return _ok({
            "summary": f"{len(rows)} gadgets known for {args['language']}"
                       + (f"/{args['library']}" if args.get('library') else ""),
            "handles": rows,
        })
    finally:
        kg.close()


def _tool_trust_shadow_analyze() -> list[TextContent]:
    from lacuna.tools.trust_shadow import analyze_application
    from lacuna.kg import Capability, open_kg
    repos = _repo_paths()
    if not repos:
        return _err("no repos configured")
    result = analyze_application(repos)
    # Write to KG
    try:
        kg = open_kg()
        # Index hints to capability IDs
        name_to_cap_id: dict[str, str] = {}
        for repo_name, rep in result["per_repo"].items():
            for cap in rep["capabilities"]:
                c = Capability(
                    asset_kind=cap["asset_kind"],
                    asset_name=cap["asset_name"],
                    holder_repo=cap["holder_repo"],
                    grants=[],
                )
                cid = kg.add_capability(c)
                name_to_cap_id[cap["asset_name"]] = cid
        for edge in result["resolved_edges"]:
            cap_id = name_to_cap_id.get(edge["to_asset_name"])
            if cap_id:
                kg.add_capability_edge(
                    edge["from_repo"], cap_id, edge["relationship"],
                    f"via {edge.get('via_file')}:{edge.get('via_line')}",
                )
        kg.close()
    except Exception as e:
        result["kg_write_error"] = str(e)
    # Return a digest (full data is verbose)
    return _ok({
        "summary": result["summary"],
        "facets": {
            "cross_repo_trust_paths_count": len(result["cross_repo_trust_paths"]),
            "capabilities_count": sum(
                len(r["capabilities"]) for r in result["per_repo"].values()
            ),
            "resolved_edges": len(result["resolved_edges"]),
            "unresolved_hints": len(result["unresolved_hints"]),
        },
        "cross_repo_trust_paths": result["cross_repo_trust_paths"][:50],
    })


def _tool_fetch_payload(args: dict) -> list[TextContent]:
    ref = args["payload_ref"]
    page = int(args.get("page", 0))
    page_size = int(args.get("page_size_bytes", 32000))
    p = Path(ref)
    if not p.exists() or not str(p).startswith(str(TOOL_CACHE)):
        return _err(f"unknown payload_ref: {ref}")
    raw = p.read_text()
    start = page * page_size
    end = start + page_size
    return _ok({
        "summary": f"payload chunk page={page} bytes={start}..{end} of {len(raw)}",
        "chunk": raw[start:end],
        "more": end < len(raw),
        "next_page": page + 1 if end < len(raw) else None,
    })


# ─── v3 Layer 2: precision tool implementations ────────────────────────────

def _resolve_repo_root(repo_name: str) -> Path | None:
    """Find a repo directory by manifest name, falling back to workspace."""
    manifest = _load_manifest()
    for r in manifest.get("repos", []):
        if r.get("name") == repo_name:
            return WORKSPACE / r.get("path", repo_name)
    candidate = WORKSPACE / repo_name
    if candidate.is_dir():
        return candidate
    return None


def _persist_precision_findings(findings: list[dict]) -> None:
    """Write precision findings to the KG."""
    try:
        from lacuna.kg import open_kg
        kg = open_kg()
        for f in findings:
            kg.add_precision_finding(
                kind=f["kind"],
                repo=f["repo"], file=f["file"], line=f["line"],
                function_qual=f.get("function_qual"),
                cwe=f.get("cwe"),
                detail_md=f["detail_md"],
                evidence=f.get("evidence", {}),
                confidence=f["confidence"],
                cve_hint=f.get("cve_hint"),
            )
        kg.close()
    except Exception:
        # KG persistence is opportunistic; tool still returns its findings
        pass


def _tool_integer_range_analysis(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    from lacuna.precision import analyze_integer_range
    result = analyze_integer_range(root, repo_name=repo)
    _persist_precision_findings(result["findings"])
    return _ok({
        "summary": result["summary"],
        "facets": _facet_findings(result["findings"]),
        "findings_count": len(result["findings"]),
        "sample": result["findings"][:5],
    })


def _tool_lifetime_analysis(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    from lacuna.precision import analyze_lifetime
    result = analyze_lifetime(root, repo_name=repo)
    _persist_precision_findings(result["findings"])
    return _ok({
        "summary": result["summary"],
        "facets": _facet_findings(result["findings"]),
        "findings_count": len(result["findings"]),
        "sample": result["findings"][:5],
    })


def _tool_format_string_sinks(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    # Cross-reference dependency_graph for log4j version hint
    dep_hint = _extract_dep_hint(repo)
    from lacuna.precision import analyze_format_string
    result = analyze_format_string(
        root, repo_name=repo,
        languages=args.get("languages"),
        dependency_hint=dep_hint,
    )
    _persist_precision_findings(result["findings"])
    return _ok({
        "summary": result["summary"],
        "facets": _facet_findings(result["findings"]),
        "findings_count": len(result["findings"]),
        "sample": result["findings"][:5],
    })


def _tool_type_confusion_sites(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    from lacuna.precision import analyze_type_confusion
    result = analyze_type_confusion(root, repo_name=repo)
    _persist_precision_findings(result["findings"])
    return _ok({
        "summary": result["summary"],
        "facets": _facet_findings(result["findings"]),
        "findings_count": len(result["findings"]),
        "sample": result["findings"][:5],
    })


def _tool_allocator_map(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    from lacuna.precision import analyze_allocator_map
    result = analyze_allocator_map(root, repo_name=repo)
    return _ok({
        "summary": result["summary"],
        "global_allocators": result["global_allocators"],
        "custom_pairs": result["custom_pairs"],
        "gfp_flags": result.get("gfp_flags", {}),
    })


def _facet_findings(findings: list[dict]) -> dict:
    """Group findings by kind+CWE for compact UI display."""
    from collections import Counter
    facets: dict[str, int] = Counter()
    for f in findings:
        key = f"{f.get('kind','?')}:{f.get('cwe','?')}"
        facets[key] += 1
    return dict(facets)


def _extract_dep_hint(repo: str) -> dict:
    """Pull dependency_graph hints from the KG to inform precision tools."""
    try:
        from lacuna.kg import open_kg
        kg = open_kg()
        rows = kg._conn.execute(
            "SELECT name, version FROM dependencies WHERE repo = ? LIMIT 500",
            (repo,),
        ).fetchall()
        kg.close()
        return {r["name"]: r["version"] for r in rows if r["version"]}
    except Exception:
        return {}


# ─── v3 Layer 3: dynamic confirmation ──────────────────────────────────────

def _tool_sanitizer_build(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    sanitizers = args.get("sanitizers", "asan,ubsan")
    timeout = int(args.get("timeout_seconds", 1800))

    # Memoize: if we already built this repo at this git_sha, return cached
    try:
        from lacuna.kg import open_kg
        kg = open_kg()
        git_sha = _git_sha(root)
        if git_sha:
            cached = kg.latest_sanitizer_build(repo, git_sha, sanitizers)
            if cached and cached.get("status") == "success":
                kg.close()
                return _ok({
                    "summary": f"sanitizer_build cached: {cached['status']}",
                    "cached": True,
                    "result": {
                        "status": cached["status"],
                        "build_system": cached.get("build_system"),
                        "binaries": json.loads(cached.get("binaries_json") or "[]"),
                        "warnings": json.loads(cached.get("warnings_json") or "[]"),
                        "duration_s": cached["duration_s"],
                    },
                })
        kg.close()
    except Exception:
        git_sha = None

    from lacuna.dynamic.sanitizer_build import build, to_dict
    result = build(root, sanitizers=sanitizers, timeout_seconds=timeout)

    # Persist
    if git_sha:
        try:
            kg = open_kg()
            kg.record_sanitizer_build(
                repo=repo, git_sha=git_sha, sanitizers=sanitizers,
                build_system=result.build_system,
                status=result.status,
                build_log_path=result.build_log_path,
                binaries=result.binaries,
                warnings=result.warnings,
                duration_s=result.duration_s,
            )
            kg.close()
        except Exception:
            pass

    return _ok({
        "summary": (
            f"sanitizer_build: {result.status} "
            f"({result.build_system or 'unknown'}, {result.duration_s}s)"
        ),
        "cached": False,
        "result": to_dict(result),
    })


def _git_sha(repo_root: Path) -> str | None:
    try:
        p = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if p.returncode == 0:
            return p.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ─── v3 Layer 4: patches ───────────────────────────────────────────────────

def _tool_patch_essence(args: dict) -> list[TextContent]:
    repo = args["repo"]
    commit_sha = args["commit_sha"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    from lacuna.patches import extract_essence
    essence = extract_essence(commit_sha=commit_sha, repo_root=root)
    if not essence:
        return _err(f"could not extract essence for {commit_sha}")

    # Persist the rule
    pr_id = None
    try:
        from lacuna.kg import open_kg
        kg = open_kg()
        pr_id = kg.add_patch_rule(
            source_kind="internal_commit",
            source_ref=commit_sha,
            repo=repo,
            bug_class=essence.bug_class,
            rule_yaml=essence.rule_yaml,
            before_pattern=essence.before_pattern,
            after_pattern=essence.after_pattern,
            essence_md=essence.essence_md,
            confidence=essence.confidence,
        )
        kg.close()
    except Exception:
        pass

    return _ok({
        "summary": (
            f"patch_essence: {essence.bug_class or 'unclassified'} "
            f"({essence.confidence:.2f} confidence) — "
            f"{len(essence.files_changed)} files"
        ),
        "rule_id": pr_id,
        "bug_class": essence.bug_class,
        "files_changed": essence.files_changed,
        "before_pattern": essence.before_pattern,
        "after_pattern": essence.after_pattern,
        "essence_md": essence.essence_md,
        "rule_yaml": essence.rule_yaml,
        "confidence": essence.confidence,
    })


def _tool_propagate_pattern(args: dict) -> list[TextContent]:
    repo = args["repo"]
    root = _resolve_repo_root(repo)
    if not root:
        return _err(f"unknown repo: {repo}")
    rule_yaml = args.get("rule_yaml", "")
    rule_id = args.get("rule_id")

    # If rule_id provided, fetch from KG
    if rule_id and not rule_yaml:
        try:
            from lacuna.kg import open_kg
            kg = open_kg()
            row = kg.get_patch_rule(rule_id)
            kg.close()
            if not row:
                return _err(f"unknown rule_id: {rule_id}")
            rule_yaml = row["rule_yaml"]
        except Exception as e:
            return _err(f"failed to load rule: {e}")

    if not rule_yaml:
        return _err("provide either rule_yaml or rule_id")

    from lacuna.patches import propagate_pattern
    result = propagate_pattern(root, rule_yaml)
    return _ok({
        "summary": result["summary"],
        "match_count": len(result["matches"]),
        "matches": result["matches"][:50],
    })


def _tool_fetch_payload(args: dict) -> list[TextContent]:
    ref = args["payload_ref"]
    page = int(args.get("page", 0))
    page_size = int(args.get("page_size_bytes", 32000))
    p = Path(ref)
    if not p.exists() or not str(p).startswith(str(TOOL_CACHE)):
        return _err(f"unknown payload_ref: {ref}")
    raw = p.read_text()
    start = page * page_size
    end = start + page_size
    return _ok({
        "summary": f"payload chunk page={page} bytes={start}..{end} of {len(raw)}",
        "chunk": raw[start:end],
        "more": end < len(raw),
        "next_page": page + 1 if end < len(raw) else None,
    })


# ─── entrypoint ─────────────────────────────────────────────────────────────

async def _amain() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
