---
name: minimal-repro
description: After a finding is confirmed, produce the SMALLEST input that still triggers it. Use during validator's post-confirmation phase; the stop hook will refuse to end the scan until every finding has a minimal repro recorded.
---

# Minimal repro

A finding without a minimal repro is a finding the human triager will spend
30 minutes redo-ing. Cut that time to 30 seconds: after confirmation, the
validator must record the smallest reproducing payload in the KG via
`kg.write.minimal_repro`.

This is non-negotiable. The stop hook checks
`kg.read.findings_lacking_repros` before allowing the scan to conclude.

## What "minimal" means

The smallest payload (in bytes and in conceptual steps) that:
1. Triggers the bug deterministically (≥ 3 consecutive runs).
2. Requires no setup beyond what's documented in `prerequisites`.
3. Is human-readable enough that a triager can paste it into a curl/etc.

Minimal does NOT mean "shortest possible string." It means "no fat." A
`?id=1' UNION SELECT NULL,version()--` is more minimal than
`?id=1' UNION SELECT NULL,NULL,NULL,NULL,version(),NULL,NULL--` even if
both are similar length — fewer columns hits the same primitive faster.

## Procedure

### Step 1 — start from the confirming payload

The validator's confirming payload is your starting point. Note its
length in bytes and its conceptual complexity (number of HTTP requests,
number of headers added, number of body fields modified).

### Step 2 — binary search on body

If the payload is a JSON/form body, halve it. Remove half the fields. Does
the bug still fire? If yes, repeat on the remaining half. If no, restore
those fields and remove the other half. Continue until removing ANY field
breaks the repro.

### Step 3 — minimize each field's content

For each remaining field, find the smallest substring that still triggers.
For SQLi, try shrinking the payload character by character. For XSS, try
the standard short payloads (`<svg/onload=1>`, `<img src=x onerror=1>`)
before falling back to ad-hoc obfuscation.

### Step 4 — strip headers

Remove headers one at a time. Most are noise. Keep:
- The Host header (always required).
- The auth header (if the finding requires auth — note this is a
  prerequisite, not a payload bit).
- Any content-type that affects parsing.

### Step 5 — verify reproducibility

Run the minimized payload three consecutive times. If it doesn't fire all
three, you've minimized too aggressively. Back off.

### Step 6 — write it

Call `kg.write.minimal_repro` with:
- `finding_id`: the F-... ID
- `minimal_payload`: the literal payload (HTTP request, sqlmap command,
   JSON body — whatever applies). Multi-line is fine; YAML or curl format
   preferred.
- `minimization_steps`: list of dicts showing what you removed and verified.

## Worked example

Starting confirming payload (1247 bytes):
```
POST /api/orders HTTP/1.1
Host: target.local
Authorization: Bearer eyJ...
Content-Type: application/json
User-Agent: Mozilla/5.0 ...
Accept: application/json
Accept-Encoding: gzip
X-Request-Id: 04f9c0a4-...
{
  "items": [
    {"sku": "ABC", "qty": 1, "options": {"gift_wrap": false}},
    {"sku": "DEF", "qty": 2}
  ],
  "discount_code": "'; UPDATE orders SET status='paid' WHERE 1=1--",
  "shipping_address": {"line1": "...", "city": "...", "zip": "..."}
}
```

After minimization:
```
POST /api/orders HTTP/1.1
Host: target.local
Authorization: Bearer <REDACTED>
Content-Type: application/json

{"items":[{"sku":"X","qty":1}],"discount_code":"';UPDATE orders SET status='paid'--"}
```

Minimization log:
```
- removed User-Agent / Accept / Accept-Encoding / X-Request-Id headers — bug still fires.
- shrunk items[0] (removed options, removed items[1]) — still fires.
- removed shipping_address entirely — still fires.
- shrunk SKU "ABC" → "X" — still fires.
- shrunk SQL payload: removed " WHERE 1=1" → still fires (UPDATE without WHERE updates all rows).
- removed trailing space before `--` → still fires.
- attempt: remove discount_code field entirely → bug does NOT fire (sanity).
```

Final size: 192 bytes. ~6× smaller. Triagers can now paste this directly.

## When minimization is hard

Some bugs require state setup that can't be shrunk (a chain of 3
sequential requests). In that case, minimize EACH request and document
the request-sequence as the "payload." `minimization_steps` should
record why each request is necessary.

## Cost discipline

Minimization is bounded: at most 12 reduction attempts per finding. If
after 12 attempts you haven't converged, write the best minimization you
have and move on. Diminishing returns kick in fast.
