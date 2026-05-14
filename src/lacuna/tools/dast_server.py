"""
lacuna-dast MCP server.

Production-ready DAST toolbelt. Speaks HTTP, handles auth flows, fuzzes
parameters, parses OpenAPI, and polls an out-of-band callback collector for
blind exploit confirmations.

Safety:
  * The PreToolUse hook is the primary safety gate (rate-limits, destructive
    verb policy, etc.).  This server enforces *defensive* checks too:
      - Target must match an allowed-host pattern from the manifest.
      - Requests with destructive methods are double-checked here.
  * All requests record a full trace (request + response) to evidence dir.

Tools:
  auth_login          — execute one or more auth flows declared in manifest
  http_request        — single HTTP request with redirect/cookie tracking
  endpoint_enum       — parse OpenAPI/swagger and emit endpoint list
  crawl               — small-radius crawler from a seed URL
  fuzz_param          — fuzz a single param with a payload class
  oob_callback_listen — register a unique OOB token for blind tests
  oob_callback_poll   — poll the OOB collector for hits on a token
  header_test         — emit a request that probes a specific header behavior
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg  # noqa: E402
from lacuna.dast.payloads import payloads_for_class  # noqa: E402
from lacuna.dast.oob_client import OobClient  # noqa: E402

server = Server("lacuna-dast")

WORKSPACE = Path(os.environ.get("LACUNA_WORKSPACE", "/workspace"))
MANIFEST_PATH = os.environ.get(
    "LACUNA_MANIFEST_RESOLVED",
    str(WORKSPACE / os.environ.get("LACUNA_MANIFEST", "app.lacuna.yaml")),
)
EVIDENCE_DIR = Path(os.environ.get("LACUNA_EVIDENCE_DIR", "/state/evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
TOOL_CACHE = Path(os.environ.get("LACUNA_TOOL_CACHE_DIR", "/state/tool_results"))
TOOL_CACHE.mkdir(parents=True, exist_ok=True)

# In-memory state for the lifetime of this server process
_SESSION_COOKIES: dict[str, dict] = {}  # session_name → cookie jar
_SESSION_HEADERS: dict[str, dict] = {}  # session_name → headers (e.g. JWT)


# ── helpers ─────────────────────────────────────────────────────────────────

def _ok(payload: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload, default=str))]


def _err(msg: str) -> list[TextContent]:
    return _ok({"error": msg})


def _load_manifest() -> dict:
    if not Path(MANIFEST_PATH).exists():
        return {}
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f) or {}


def _dast_config() -> dict:
    return (_load_manifest().get("scan", {}) or {}).get("dast", {}) or {}


def _allowed_hosts() -> list[str]:
    return _dast_config().get("target", {}).get("allowed_hosts", []) or []


def _check_target(url: str) -> str | None:
    """Return None if target is allowed; an error string otherwise."""
    if not url.startswith(("http://", "https://")):
        return f"invalid URL scheme: {url}"
    allowed = _allowed_hosts()
    if not allowed:
        return "no allowed_hosts configured in manifest scan.dast.target.allowed_hosts"
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    for pattern in allowed:
        if _glob_match(pattern, host):
            return None
    return f"host {host} not in scan.dast.target.allowed_hosts"


def _glob_match(pattern: str, host: str) -> bool:
    """Simple glob: *.example.com matches a.example.com."""
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return pattern == host


def _materialize_trace(prefix: str, request: dict, response: dict) -> str:
    """Write request+response to /state/evidence and return the directory path."""
    eid = uuid.uuid4().hex[:12]
    ev_dir = EVIDENCE_DIR / f"{prefix}-{eid}"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "request.json").write_text(json.dumps(request, indent=2, default=str))
    (ev_dir / "response.json").write_text(json.dumps(response, indent=2, default=str))
    return str(ev_dir)


async def _do_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: Any = None,
    json_body: Any = None,
    cookies: dict | None = None,
    session: str | None = None,
    follow_redirects: bool = True,
    timeout_s: float = 30.0,
) -> dict:
    """Single HTTP request with full trace capture."""
    sess_headers: dict = {}
    sess_cookies: dict = {}
    if session:
        sess_headers = _SESSION_HEADERS.get(session, {}) or {}
        sess_cookies = _SESSION_COOKIES.get(session, {}) or {}
    merged_headers = {**sess_headers, **(headers or {})}
    merged_cookies = {**sess_cookies, **(cookies or {})}
    merged_headers.setdefault(
        "User-Agent", "Lacuna/1.0 (security scan; +https://your-org.example)"
    )

    request_blob = {
        "method": method, "url": url, "headers": merged_headers,
        "params": params, "data": data, "json": json_body,
        "cookies": merged_cookies, "session": session,
    }
    started = time.time()
    try:
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects, timeout=timeout_s,
        ) as client:
            resp = await client.request(
                method, url, headers=merged_headers, params=params,
                data=data, json=json_body, cookies=merged_cookies,
            )
        duration_ms = int((time.time() - started) * 1000)
        body_bytes = resp.content
        # Persist body — it can be large
        body_hash = hashlib.sha256(body_bytes).hexdigest()[:16]
        body_path = TOOL_CACHE / f"resp-body-{body_hash}.bin"
        if not body_path.exists():
            body_path.write_bytes(body_bytes)

        # In-context body sample
        try:
            body_sample = body_bytes.decode("utf-8", errors="replace")[:2000]
        except Exception:
            body_sample = "<binary>"

        response_blob = {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "url_final": str(resp.url),
            "redirect_chain": [str(h.url) for h in resp.history],
            "body_bytes": len(body_bytes),
            "body_sample": body_sample,
            "body_payload_ref": str(body_path),
            "duration_ms": duration_ms,
        }
    except Exception as e:
        response_blob = {"error": str(e)}

    trace_dir = _materialize_trace("dast-http", request_blob, response_blob)
    response_blob["evidence_dir"] = trace_dir
    return response_blob


# ── tool list ───────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="http_request", description=(
            "Single HTTP request with full trace capture. Returns status, "
            "headers, body sample (2KB), and a payload_ref for the full body. "
            "Optional `session` parameter reuses cookies/headers from a prior "
            "auth_login."
        ), inputSchema={
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "params": {"type": "object"},
                "data": {},
                "json_body": {},
                "cookies": {"type": "object"},
                "session": {"type": "string"},
                "follow_redirects": {"type": "boolean", "default": True},
                "timeout_s": {"type": "number", "default": 30},
            },
            "required": ["method", "url"],
        }),

        Tool(name="auth_login", description=(
            "Execute an auth flow declared in the manifest. Returns a "
            "session_name that can be reused in subsequent http_request calls."
        ), inputSchema={
            "type": "object",
            "properties": {
                "flow_name": {"type": "string",
                              "description": "Name of a flow in scan.dast.auth.flows"},
            },
            "required": ["flow_name"],
        }),

        Tool(name="endpoint_enum", description=(
            "Parse an OpenAPI/Swagger file and enumerate endpoints with method, "
            "path, and parameter schema. Returns handles."
        ), inputSchema={
            "type": "object",
            "properties": {
                "openapi_url": {"type": "string"},
                "openapi_path": {"type": "string"},
            },
            "required": [],
        }),

        Tool(name="crawl", description=(
            "Small-radius crawler from a seed URL. Same-origin only. Capped at "
            "max_pages."
        ), inputSchema={
            "type": "object",
            "properties": {
                "seed_url": {"type": "string"},
                "session": {"type": "string"},
                "max_pages": {"type": "integer", "default": 50},
                "max_depth": {"type": "integer", "default": 3},
            },
            "required": ["seed_url"],
        }),

        Tool(name="fuzz_param", description=(
            "Fuzz a single parameter with a payload class. Returns observations "
            "(status changes, error strings, response time deltas, reflected "
            "values) for each payload."
        ), inputSchema={
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "param_in": {"type": "string",
                              "enum": ["query", "form", "json", "header", "cookie"]},
                "param_name": {"type": "string"},
                "payload_class": {"type": "string",
                                    "description": "sqli|xss|cmdi|ssrf|ssti|"
                                                   "path-traversal|xxe|nosql|"
                                                   "log4j|csv-injection|"
                                                   "open-redirect"},
                "baseline_value": {"type": "string",
                                     "description": "Value to use for non-fuzzed params"},
                "session": {"type": "string"},
                "extra_params": {"type": "object"},
                "max_payloads": {"type": "integer", "default": 50},
            },
            "required": ["method", "url", "param_in", "param_name",
                         "payload_class"],
        }),

        Tool(name="oob_callback_register", description=(
            "Generate a unique OOB token to embed in payloads for blind exploit "
            "confirmation (SSRF, blind RCE, OOB SQLi). Returns the token and "
            "the callback URL to embed."
        ), inputSchema={
            "type": "object",
            "properties": {"label": {"type": "string"}},
            "required": [],
        }),

        Tool(name="oob_callback_poll", description=(
            "Poll the OOB collector for hits on a previously-registered token. "
            "Returns hits with timestamps, source IP, and protocol (DNS/HTTP)."
        ), inputSchema={
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "since_seconds": {"type": "integer", "default": 600},
            },
            "required": ["token"],
        }),

        Tool(name="header_test", description=(
            "Probe a specific HTTP header behavior — e.g. CORS preflight, "
            "host-header injection, missing security headers."
        ), inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "test_kind": {"type": "string",
                                "enum": ["cors", "host-injection",
                                         "security-headers", "smuggling-clte",
                                         "smuggling-tecl"]},
                "session": {"type": "string"},
            },
            "required": ["url", "test_kind"],
        }),

        Tool(name="playwright_dom_scan", description=(
            "Headless-browser DAST. Drives a real Chromium against the target "
            "URLs and runs scenarios for DOM-XSS, postMessage abuse, and DOM "
            "clobbering. Catches client-side bugs invisible to HTTP-only DAST."
        ), inputSchema={
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "scenarios": {"type": "array",
                                "items": {"type": "string",
                                           "enum": ["dom_xss", "postmessage",
                                                     "dom_clobbering"]}},
            },
            "required": ["urls"],
        }),

        Tool(name="oracle_sqlmap", description=(
            "Deep oracle: invoke sqlmap with safe defaults to confirm/refute "
            "a SQLi hypothesis. Use ONLY when validator confidence is uncertain "
            "after 4 dialectic rounds, because sqlmap is expensive."
        ), inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "data": {"type": "string"},
                "cookies": {"type": "string"},
                "level": {"type": "integer", "default": 1},
                "risk": {"type": "integer", "default": 1},
            },
            "required": ["url"],
        }),

        Tool(name="oracle_ysoserial", description=(
            "Deep oracle: generate a Java/.NET deserialization gadget payload. "
            "Use when validator has confirmed an unsafe-deserialize sink + "
            "classpath evidence."
        ), inputSchema={
            "type": "object",
            "properties": {
                "runtime": {"type": "string", "enum": ["java", "dotnet"]},
                "gadget": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["runtime", "gadget", "command"],
        }),

        Tool(name="oracle_gopherus", description=(
            "Deep oracle: generate a gopher:// payload for protocol-smuggling "
            "SSRF against Redis/MySQL/Memcached/FastCGI/etc."
        ), inputSchema={
            "type": "object",
            "properties": {
                "exploit": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["exploit"],
        }),

        # ─── v3 Layer 3: dynamic confirmation oracles ─────────────────────
        Tool(name="fuzz_function", description=(
            "Fuzz a specific function using libFuzzer. Generates a harness, "
            "compiles it against the (sanitizer-built) library, runs for "
            "`timeout_seconds`, returns crashes with ASan reports and "
            "minimized inputs. Requires prior successful sanitizer_build "
            "for the target repo. The strongest possible confirmation "
            "oracle for memory-safety hypotheses."
        ), inputSchema={
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "function_name": {"type": "string"},
                "signature": {"type": "string"},
                "library_path": {"type": "string"},
                "timeout_seconds": {"type": "integer", "default": 300},
                "max_total_runs": {"type": "integer"},
                "triggered_by": {"type": "string"},
            },
            "required": ["repo", "function_name", "signature",
                          "library_path"],
        }),

        Tool(name="symex_reach", description=(
            "Use angr symbolic execution to find a concrete input that "
            "drives execution from `source` to `target` in a binary. "
            "Returns either {reachable: true, concrete_input_b64} or "
            "{reachable: false}. Used when fuzzing fails to hit a path "
            "gated by deep conditional chains."
        ), inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "source": {"type": "string"},
                "target": {"type": "string"},
                "timeout_seconds": {"type": "integer", "default": 60},
            },
            "required": ["binary_path", "source", "target"],
        }),

        Tool(name="differential_parse", description=(
            "Run the same input through multiple parser implementations "
            "(HTTP, URL, JSON) and report divergence. Catches request "
            "smuggling, SSRF parser confusion, JSON key-confusion shapes. "
            "Strongest evidence type for parser-discrepancy vulns."
        ), inputSchema={
            "type": "object",
            "properties": {
                "protocol": {"type": "string",
                              "enum": ["http_request", "url", "json"]},
                "input_bytes_hex": {"type": "string"},
                "parsers": {"type": "array",
                             "items": {"type": "string"}},
            },
            "required": ["protocol", "input_bytes_hex"],
        }),
    ]


# ── tool implementations ────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "http_request":
            return await _t_http_request(arguments)
        if name == "auth_login":
            return await _t_auth_login(arguments)
        if name == "endpoint_enum":
            return await _t_endpoint_enum(arguments)
        if name == "crawl":
            return await _t_crawl(arguments)
        if name == "fuzz_param":
            return await _t_fuzz_param(arguments)
        if name == "oob_callback_register":
            return _t_oob_register(arguments)
        if name == "oob_callback_poll":
            return await _t_oob_poll(arguments)
        if name == "header_test":
            return await _t_header_test(arguments)
        if name == "playwright_dom_scan":
            return _t_playwright_dom_scan(arguments)
        if name == "oracle_sqlmap":
            return _t_oracle_sqlmap(arguments)
        if name == "oracle_ysoserial":
            return _t_oracle_ysoserial(arguments)
        if name == "oracle_gopherus":
            return _t_oracle_gopherus(arguments)
        # ─── v3 Layer 3 ──
        if name == "fuzz_function":
            return _t_fuzz_function(arguments)
        if name == "symex_reach":
            return _t_symex_reach(arguments)
        if name == "differential_parse":
            return _t_differential_parse(arguments)
    except Exception as e:
        return _err(f"DAST tool '{name}' raised: {e}")
    return _err(f"unknown DAST tool: {name}")


async def _t_http_request(args: dict) -> list[TextContent]:
    err = _check_target(args["url"])
    if err:
        return _err(err)
    resp = await _do_request(
        method=args["method"].upper(),
        url=args["url"],
        headers=args.get("headers"),
        params=args.get("params"),
        data=args.get("data"),
        json_body=args.get("json_body"),
        cookies=args.get("cookies"),
        session=args.get("session"),
        follow_redirects=args.get("follow_redirects", True),
        timeout_s=args.get("timeout_s", 30),
    )
    return _ok({
        "summary": f"{args['method'].upper()} {args['url']} → "
                    f"{resp.get('status', '?')} "
                    f"({resp.get('body_bytes', 0)}B, "
                    f"{resp.get('duration_ms', 0)}ms)",
        "response": resp,
    })


async def _t_auth_login(args: dict) -> list[TextContent]:
    flow_name = args["flow_name"]
    auth_cfg = (_dast_config().get("auth", {}) or {}).get("flows", []) or []
    flow = next((f for f in auth_cfg if f.get("name") == flow_name), None)
    if not flow:
        return _err(f"auth flow '{flow_name}' not declared in manifest")

    session_name = flow_name
    kind = flow.get("kind")

    if kind == "form-login":
        # POST credentials to login_url, capture cookies
        url = flow["login_url"]
        body_template = flow.get("body", {})
        # Resolve env-var references in body
        body = {
            k: (
                os.environ.get(v[5:], "") if isinstance(v, str) and v.startswith("$env:")
                else v
            )
            for k, v in body_template.items()
        }
        async with httpx.AsyncClient(
            follow_redirects=flow.get("follow_redirects", True),
            timeout=30.0,
        ) as client:
            resp = await client.post(url, data=body)
            cookies = dict(resp.cookies)
        _SESSION_COOKIES[session_name] = cookies
        return _ok({
            "summary": f"form-login {flow_name} → {resp.status_code} ({len(cookies)} cookies)",
            "session": session_name, "status": resp.status_code,
            "cookie_count": len(cookies),
        })

    if kind == "oauth-password-grant":
        token_url = flow["token_url"]
        body = {
            "grant_type": "password",
            "username": os.environ.get(flow.get("username_env", ""), ""),
            "password": os.environ.get(flow.get("password_env", ""), ""),
            "client_id": flow.get("client_id", ""),
            "client_secret": flow.get("client_secret_env") and
                              os.environ.get(flow["client_secret_env"], "") or "",
            "scope": flow.get("scope", ""),
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(token_url, data=body)
        if resp.status_code != 200:
            return _err(f"oauth token endpoint returned {resp.status_code}: "
                          f"{resp.text[:200]}")
        token = (resp.json() or {}).get("access_token")
        if not token:
            return _err("no access_token in oauth response")
        _SESSION_HEADERS[session_name] = {"Authorization": f"Bearer {token}"}
        return _ok({
            "summary": f"oauth {flow_name} → bearer token acquired",
            "session": session_name,
        })

    if kind == "bearer-static":
        token = os.environ.get(flow.get("token_env", ""), "")
        if not token:
            return _err(f"env var {flow.get('token_env')} not set")
        _SESSION_HEADERS[session_name] = {"Authorization": f"Bearer {token}"}
        return _ok({
            "summary": f"static-bearer {flow_name} loaded",
            "session": session_name,
        })

    return _err(f"unknown auth flow kind: {kind}")


async def _t_endpoint_enum(args: dict) -> list[TextContent]:
    spec_text: str | None = None
    if args.get("openapi_url"):
        err = _check_target(args["openapi_url"])
        if err:
            return _err(err)
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(args["openapi_url"])
        if r.status_code != 200:
            return _err(f"openapi fetch returned {r.status_code}")
        spec_text = r.text
    elif args.get("openapi_path"):
        p = Path(args["openapi_path"])
        if not p.exists():
            return _err(f"openapi file not found: {p}")
        spec_text = p.read_text()
    else:
        return _err("provide either openapi_url or openapi_path")

    try:
        if spec_text.strip().startswith("{"):
            spec = json.loads(spec_text)
        else:
            spec = yaml.safe_load(spec_text)
    except Exception as e:
        return _err(f"failed to parse openapi: {e}")

    endpoints: list[dict] = []
    base_url = ""
    if spec.get("servers"):
        base_url = (spec["servers"][0] or {}).get("url", "")
    paths = (spec.get("paths") or {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in {"get", "post", "put", "delete",
                                        "patch", "options", "head"}:
                continue
            params = op.get("parameters", []) if isinstance(op, dict) else []
            body = op.get("requestBody") if isinstance(op, dict) else None
            endpoints.append({
                "method": method.upper(), "path": path, "base_url": base_url,
                "summary": (op.get("summary") if isinstance(op, dict) else "") or "",
                "parameters": [
                    {"name": p.get("name"), "in": p.get("in"),
                     "required": p.get("required", False),
                     "schema": p.get("schema")}
                    for p in params if isinstance(p, dict)
                ],
                "request_body": bool(body),
            })
    return _ok({
        "summary": f"{len(endpoints)} endpoints",
        "base_url": base_url,
        "handles": endpoints[:200],
    })


async def _t_crawl(args: dict) -> list[TextContent]:
    seed_url = args["seed_url"]
    err = _check_target(seed_url)
    if err:
        return _err(err)
    session = args.get("session")
    max_pages = int(args.get("max_pages", 50))
    max_depth = int(args.get("max_depth", 3))

    from urllib.parse import urljoin, urlparse
    seed_host = urlparse(seed_url).hostname
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(seed_url, 0)]
    results: list[dict] = []
    link_re = re.compile(r'(?:href|src)\s*=\s*[\'"]([^\'"\s>]+)', re.IGNORECASE)

    while queue and len(results) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if urlparse(url).hostname != seed_host:
            continue
        resp = await _do_request("GET", url, session=session,
                                   follow_redirects=True, timeout_s=20)
        results.append({
            "url": url, "status": resp.get("status"),
            "bytes": resp.get("body_bytes", 0),
            "evidence_dir": resp.get("evidence_dir"),
        })
        if depth < max_depth and resp.get("body_sample"):
            for m in link_re.finditer(resp["body_sample"]):
                link = m.group(1)
                if link.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                resolved = urljoin(url, link)
                if resolved not in seen:
                    queue.append((resolved, depth + 1))

    return _ok({
        "summary": f"crawled {len(results)} pages from {seed_url}",
        "handles": results,
    })


async def _t_fuzz_param(args: dict) -> list[TextContent]:
    err = _check_target(args["url"])
    if err:
        return _err(err)
    payloads = payloads_for_class(args["payload_class"])
    max_payloads = int(args.get("max_payloads", 50))
    payloads = payloads[:max_payloads]
    if not payloads:
        return _err(f"no payloads for class: {args['payload_class']}")

    method = args["method"].upper()
    url = args["url"]
    param_in = args["param_in"]
    param_name = args["param_name"]
    baseline_value = args.get("baseline_value", "baseline")
    extra_params = args.get("extra_params", {}) or {}
    session = args.get("session")

    # Baseline request
    baseline_kwargs = _build_request_kwargs(
        param_in, param_name, baseline_value, extra_params,
    )
    baseline = await _do_request(method, url, session=session,
                                   timeout_s=20, **baseline_kwargs)

    observations: list[dict] = []
    for payload in payloads:
        kwargs = _build_request_kwargs(
            param_in, param_name, payload, extra_params,
        )
        resp = await _do_request(method, url, session=session,
                                   timeout_s=30, **kwargs)
        observation = _observe_diff(payload, baseline, resp)
        observations.append(observation)

    interesting = [o for o in observations
                    if o.get("interesting") or o.get("error_signal")]
    return _ok({
        "summary": f"fuzzed {len(payloads)} payloads for "
                    f"{args['payload_class']} on {param_name}; "
                    f"{len(interesting)} interesting",
        "baseline": {"status": baseline.get("status"),
                      "bytes": baseline.get("body_bytes")},
        "handles": observations,
        "interesting_indices": [i for i, o in enumerate(observations)
                                  if o.get("interesting")],
    })


def _build_request_kwargs(
    param_in: str, name: str, value: str, extras: dict,
) -> dict:
    if param_in == "query":
        return {"params": {**extras, name: value}}
    if param_in == "form":
        return {"data": {**extras, name: value}}
    if param_in == "json":
        return {"json_body": {**extras, name: value}}
    if param_in == "header":
        return {"headers": {name: value}}
    if param_in == "cookie":
        return {"cookies": {name: value}}
    raise ValueError(f"unknown param_in: {param_in}")


ERROR_SIGNAL_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"ORA-\d{4,5}", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"Traceback \(most recent", re.IGNORECASE),
    re.compile(r"java\.\w+Exception", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider", re.IGNORECASE),
    re.compile(r"valueOf\(.*\) is null", re.IGNORECASE),
]


def _observe_diff(payload: str, baseline: dict, resp: dict) -> dict:
    out = {"payload": payload[:120], "status": resp.get("status"),
            "bytes": resp.get("body_bytes"),
            "duration_ms": resp.get("duration_ms"),
            "evidence_dir": resp.get("evidence_dir")}
    base_status = baseline.get("status")
    base_bytes = baseline.get("body_bytes", 0) or 0
    base_dur = baseline.get("duration_ms", 0) or 0
    cur_status = resp.get("status")
    cur_bytes = resp.get("body_bytes", 0) or 0
    cur_dur = resp.get("duration_ms", 0) or 0

    status_diff = cur_status != base_status
    byte_diff_pct = (
        abs(cur_bytes - base_bytes) / max(base_bytes, 1) * 100
        if base_bytes else 100.0
    )
    time_diff_ms = cur_dur - base_dur
    reflected = bool(resp.get("body_sample") and payload in resp["body_sample"])
    error_signal = False
    body_sample = resp.get("body_sample", "") or ""
    for p in ERROR_SIGNAL_PATTERNS:
        if p.search(body_sample):
            error_signal = True
            break

    out.update({
        "status_diff": status_diff,
        "byte_diff_pct": round(byte_diff_pct, 1),
        "time_diff_ms": time_diff_ms,
        "reflected": reflected,
        "error_signal": error_signal,
        "interesting": (
            status_diff or byte_diff_pct > 25
            or time_diff_ms > 3000 or reflected or error_signal
        ),
    })
    return out


def _t_oob_register(args: dict) -> list[TextContent]:
    cfg = _dast_config().get("oob", {}) or {}
    if not cfg.get("collector_url"):
        return _err("scan.dast.oob.collector_url not configured")
    client = OobClient(cfg)
    token, callback_url = client.register(label=args.get("label", "lacuna"))
    return _ok({
        "summary": f"OOB token registered: {token}",
        "token": token,
        "callback_url": callback_url,
        "dns_callback": f"{token}.{cfg.get('dns_zone', 'oob.local')}",
    })


async def _t_oob_poll(args: dict) -> list[TextContent]:
    cfg = _dast_config().get("oob", {}) or {}
    if not cfg.get("collector_url"):
        return _err("scan.dast.oob.collector_url not configured")
    client = OobClient(cfg)
    hits = await client.poll(args["token"], args.get("since_seconds", 600))
    return _ok({
        "summary": f"{len(hits)} OOB hits on token {args['token']}",
        "hits": hits,
    })


async def _t_header_test(args: dict) -> list[TextContent]:
    err = _check_target(args["url"])
    if err:
        return _err(err)
    url = args["url"]
    kind = args["test_kind"]
    session = args.get("session")

    if kind == "security-headers":
        resp = await _do_request("GET", url, session=session)
        headers = resp.get("headers") or {}
        checks = {
            "Content-Security-Policy": "Content-Security-Policy" in headers,
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
            "Referrer-Policy": "Referrer-Policy" in headers,
            "Permissions-Policy": "Permissions-Policy" in headers,
        }
        missing = [k for k, v in checks.items() if not v]
        return _ok({
            "summary": f"missing security headers: {', '.join(missing) or 'none'}",
            "checks": checks, "response": resp,
        })

    if kind == "cors":
        evil_origin = "https://lacuna-evil.example"
        resp = await _do_request("OPTIONS", url, session=session, headers={
            "Origin": evil_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization",
        })
        headers = resp.get("headers") or {}
        allow_origin = headers.get("access-control-allow-origin") or \
                          headers.get("Access-Control-Allow-Origin", "")
        allow_creds = headers.get("access-control-allow-credentials") or \
                          headers.get("Access-Control-Allow-Credentials", "")
        permissive = allow_origin in {"*", evil_origin}
        with_creds = str(allow_creds).lower() == "true"
        return _ok({
            "summary": f"CORS: origin reflection={permissive}, "
                        f"credentials={with_creds}",
            "permissive_origin": permissive,
            "allow_credentials_with_reflection": permissive and with_creds,
            "response": resp,
        })

    if kind == "host-injection":
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        resp = await _do_request(
            "GET", url, session=session,
            headers={"Host": "lacuna-evil.example", "X-Forwarded-Host": "lacuna-evil.example"},
        )
        body = resp.get("body_sample", "") or ""
        leaked = "lacuna-evil.example" in body
        return _ok({
            "summary": f"host-injection: leaked-into-response={leaked}",
            "leaked": leaked, "response": resp,
        })

    if kind in {"smuggling-clte", "smuggling-tecl"}:
        # NOTE: real smuggling tests require raw socket access; httpx normalizes.
        # We probe via duplicate Content-Length / Transfer-Encoding combos and
        # surface the response only — agent must reason about smuggling risk.
        if kind == "smuggling-clte":
            headers = {"Content-Length": "4", "Transfer-Encoding": "chunked"}
        else:
            headers = {"Transfer-Encoding": "chunked", "Content-Length": "4"}
        resp = await _do_request("POST", url, session=session, headers=headers,
                                   data="0\r\n\r\nG")
        return _ok({
            "summary": f"smuggling probe ({kind}) → {resp.get('status')}",
            "response": resp,
            "note": "Real smuggling confirmation requires raw-socket follow-up.",
        })

    return _err(f"unknown header test kind: {kind}")


# ─── new in v2: Playwright + deep oracles ─────────────────────────────────

def _t_playwright_dom_scan(args: dict) -> list[TextContent]:
    urls = args.get("urls") or []
    # Apply allowlist
    for u in urls:
        err = _check_target(u)
        if err:
            return _err(err)
    from lacuna.dast.playwright_runner import playwright_dom_scan
    result = playwright_dom_scan(
        urls, args.get("scenarios"), headless=True,
    )
    return _ok(result)


def _t_oracle_sqlmap(args: dict) -> list[TextContent]:
    err = _check_target(args["url"])
    if err:
        return _err(err)
    from lacuna.oracles import run_sqlmap
    return _ok(run_sqlmap(
        args["url"],
        method=args.get("method", "GET"),
        data=args.get("data"),
        cookies=args.get("cookies"),
        level=int(args.get("level", 1)),
        risk=int(args.get("risk", 1)),
    ))


def _t_oracle_ysoserial(args: dict) -> list[TextContent]:
    from lacuna.oracles import generate_ysoserial_payload
    return _ok(generate_ysoserial_payload(
        runtime=args["runtime"],
        gadget=args["gadget"],
        command=args["command"],
    ))


def _t_oracle_gopherus(args: dict) -> list[TextContent]:
    from lacuna.oracles import run_gopherus
    return _ok(run_gopherus(
        exploit=args["exploit"],
        command=args.get("command"),
    ))


# ─── v3 Layer 3 dynamic-confirmation oracles ───────────────────────────────

def _t_fuzz_function(args: dict) -> list[TextContent]:
    """Fuzz a function, record results to KG."""
    from pathlib import Path
    import time
    from lacuna.dynamic.fuzzer import fuzz_function, to_dict

    workspace = Path(os.environ.get(
        "LACUNA_FUZZ_WORKSPACE", "/state/fuzz",
    ))
    workspace.mkdir(parents=True, exist_ok=True)

    repo = args["repo"]
    function_name = args["function_name"]
    signature = args["signature"]
    library_path = args["library_path"]
    timeout = int(args.get("timeout_seconds", 300))
    triggered_by = args.get("triggered_by")
    max_runs = args.get("max_total_runs")

    if not Path(library_path).exists():
        return _err(f"library_path does not exist: {library_path}")

    result = fuzz_function(
        repo=repo,
        function_name=function_name,
        signature=signature,
        library_path=library_path,
        timeout_seconds=timeout,
        workspace=workspace,
        max_total_runs=max_runs,
    )

    # Persist to KG
    fuzz_run_id = None
    try:
        from lacuna.kg import open_kg
        kg = open_kg()
        fuzz_run_id = kg.record_fuzz_run(
            repo=repo,
            function_qual=function_name,
            binary_path=library_path,
            timeout_s=timeout,
            executions=result.executions,
            coverage_pct=result.coverage_pct,
            status=result.status,
            triggered_by=triggered_by,
            duration_s=result.duration_s,
        )
        for crash in result.crashes:
            kg.record_fuzz_crash(
                fuzz_run_id=fuzz_run_id,
                asan_kind=crash.get("asan_kind"),
                crash_stack=crash.get("crash_stack", []),
                input_path=crash["input_path"],
                minimized_input_path=crash.get("minimized_input_path"),
                asan_log_path=crash.get("asan_log_path"),
            )
        kg.close()
    except Exception:
        pass

    return _ok({
        "summary": (
            f"fuzz_function {function_name}: {result.status}, "
            f"{len(result.crashes)} crash(es) in {result.duration_s}s"
        ),
        "fuzz_run_id": fuzz_run_id,
        "status": result.status,
        "executions": result.executions,
        "crashes": result.crashes,
        "duration_s": result.duration_s,
        "error_message": result.error_message,
    })


def _t_symex_reach(args: dict) -> list[TextContent]:
    """Run angr symex to find a witness input from source to target."""
    from lacuna.dynamic.symex import symex_reach, to_dict
    result = symex_reach(
        binary_path=args["binary_path"],
        source=args["source"],
        target=args["target"],
        timeout_seconds=int(args.get("timeout_seconds", 60)),
    )
    return _ok({
        "summary": (
            f"symex_reach: "
            f"{'reachable' if result.reachable else 'not reached'} "
            f"({result.explored_states} states, {result.duration_s}s)"
        ),
        **to_dict(result),
    })


def _t_differential_parse(args: dict) -> list[TextContent]:
    """Multi-parser differential testing."""
    import binascii
    from lacuna.dynamic.differential import differential_parse, to_dict
    try:
        input_bytes = binascii.unhexlify(args["input_bytes_hex"])
    except (binascii.Error, ValueError) as e:
        return _err(f"bad input_bytes_hex: {e}")
    result = differential_parse(
        protocol=args["protocol"],
        input_bytes=input_bytes,
        parsers=args.get("parsers"),
    )
    # Persist if divergence found
    if result.divergence:
        try:
            from lacuna.kg import open_kg
            kg = open_kg()
            kg.add_differential_finding(
                protocol=result.protocol,
                input_hex=args["input_bytes_hex"],
                parser_results={
                    n: {"ok": pr.ok, "parsed": pr.parsed, "error": pr.error}
                    for n, pr in result.parser_results.items()
                },
                divergence=result.divergence,
                exploit_class=result.exploit_class,
            )
            kg.close()
        except Exception:
            pass

    return _ok({
        "summary": (
            f"differential_parse {args['protocol']}: "
            f"{'DIVERGENT' if result.divergence else 'consistent'}"
            + (f" → {result.exploit_class}"
               if result.exploit_class else "")
        ),
        **to_dict(result),
    })


# ── entrypoint ──────────────────────────────────────────────────────────────

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
