---
name: cross-hunter-observations
description: Use the shared observation board to broadcast non-hypothesis facts to other hunters and to read facts discovered before you. Read at hunter start; write whenever you find something other hunters could use.
---

# Cross-hunter observations

Hunters run in parallel and in isolation by default. That isolation is
intentional (token budgets, no cross-contamination of reasoning) — but it
costs us shared learning. The **observation board** is the surgical fix.

An "observation" is a fact about the app that's:
- **Useful to other hunters** (changes their calibration or their search).
- **NOT a hypothesis** (it's a derived fact, not a candidate vulnerability).
- **Verifiable** (someone could check it).

Examples that ARE observations:
- "Middleware `auth_check` is bypassed when X-Original-URL is set" (kind=middleware_bypass)
- "Sanitizer `clean_html` doesn't escape `<svg onload>`" (kind=sanitizer_bypass)
- "Flask config has `JSONIFY_PRETTYPRINT_REGULAR=False`, hiding errors" (kind=framework_quirk)
- "auth-svc:src/secrets/jwt.key is read at boot by api-svc" (kind=secret_location)
- "Function `parse_order_id()` is reachable from 6 handlers" (kind=reachability_fact)

Examples that are NOT observations (they're hypotheses or findings):
- "The /api/orders endpoint has SQLi" (hypothesis)
- "I think the JWT signing is wrong" (vague; just write a hypothesis)
- "log4j-core 2.14 is on classpath" (this is recon output, not an observation)

## When to READ observations

At the start of every hunter run, call:
```
kg.read.observations(shape=YOUR_SHAPE)
```
where YOUR_SHAPE is one of: `injection`, `authn-authz`, `crypto`,
`deserialization`, `business-logic`, `race-toctou`, `cross-service`,
`memory`.

This returns observations other hunters have tagged as relevant to YOUR
shape. Read them BEFORE planning your search — they may rule out whole
branches.

## When to WRITE observations

Write whenever:
1. You confirm a fact that another hunter would want to know.
2. You DIS-confirm something (e.g. "sanitizer X is actually correct" —
   prevents others from re-investigating).
3. You discover a shared resource (file, env var, DB row) that multiple
   services touch.

DON'T write when:
- The fact is part of a finding you're already filing (it'll be in the
  finding's prerequisites).
- You're not sure (write the hypothesis instead).
- The fact is obvious from recon's output (e.g. "this app uses Flask" —
  recon already told everyone).

## Calibration impact

Other hunters use observations to **calibrate**, not to copy. Reading
"middleware_bypass via X-Original-URL" doesn't mean every authn-authz
hunter must investigate it — it means their hypotheses involving that
middleware should be at HIGHER confidence (or LOWER, if the observation
shows a check IS present).

Two rules:
- **A positive observation (a bypass exists) RAISES confidence** for
  related hypotheses by ~0.1.
- **A negative observation (a check is correct) LOWERS confidence** for
  related hypotheses by ~0.2 (false-positive prevention is more valuable
  than discovery).

## Canonical kinds reference

| kind | when to use |
|---|---|
| `middleware_bypass` | A middleware can be skipped/spoofed |
| `sanitizer_bypass` | A sanitizer doesn't fully sanitize |
| `framework_quirk` | Framework defaults that surprise (e.g. trailing slash routing) |
| `secret_location` | Where a secret is read from / cached |
| `trust_boundary_hole` | (written by trust-shadow-analyzer) |
| `shared_state` | A resource (DB table, file, env) touched by multiple services |
| `reachability_fact` | A function is/isn't reachable from a class of entrypoints |
| `library_gadget` | A known gadget chain is applicable here |

## Format

When writing, the `summary` should be ≤120 chars, scannable. `detail_md`
can be longer with file:line evidence. `affects_shapes` is a list of
hunter shapes that should see this on their next read.

Example:
```
kg.write.observation(
  author_agent="hunter-authn-authz",
  kind="middleware_bypass",
  repo="api-svc",
  file="src/middleware/auth.py",
  line=87,
  summary="auth middleware bypassed when X-Original-URL header is set (NGINX-style overlay)",
  detail_md="At api-svc:src/middleware/auth.py:87, the middleware reads request.url to apply the allowlist. NGINX's X-Original-URL header in a reverse-proxy setup overrides this. Tested confirmed bypass to /admin/* with header X-Original-URL: /healthz.",
  affects_shapes=["authn-authz", "injection", "cross-service", "business-logic"]
)
```

## Hygiene

If you find an observation that's been written 3+ times (`seen_count >=
3`), don't write a 4th — the swarm already has it. Call
`kg.read.observations` to check.

If you reference an observation in a hypothesis, increment its `seen_count`
via `kg.increment_observation_seen` — this helps the validator calibrate.
