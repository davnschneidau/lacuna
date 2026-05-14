---
name: report-tech
description: |
  How to compose the technical report. Full per-finding template; refuted
  hypotheses included as audit trail; primitives and chains as separate
  sections. Reader is a security engineer or developer doing remediation.
---

# Technical report style

The technical report is a remediation manual. The reader is going to use it
to fix things. Make it scannable, complete, and unambiguous.

## Per-finding template

Every confirmed finding gets this block:

```markdown
### {Finding title}

**ID:** `fnd-xyz`
**Severity:** **CRITICAL**
**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**CWEs:** CWE-89, CWE-20
**Affected repos:** api, internal-api
**Source hypothesis:** `hyp-abc`

#### Validator summary

{2-4 paragraph technical description. What the bug is, where it is, how to
trigger it, what an attacker gets. Cite line numbers. Use caveman style.}

#### Evidence

- **http_trace** — `/state/evidence/dast-http-abc123/`
- **code_excerpt** — `api/db.py:200-230`
- **oob_callback** — `/state/evidence/oob-hit-xyz/`

#### Remediation

{Specific fix steps. Concrete code/config changes preferred. If multiple
fix strategies exist, list them with trade-offs.}

---
```

The four headers are non-negotiable. Always include validator summary,
evidence, remediation, even if remediation is "see CWE-89 best practices."

## Severity discipline

The severity must match the validator's verdict, not be inflated for
attention. The validator's severity rule:

- **Critical** — direct or near-direct path to RCE, full data exfil, or
  full account takeover, OR any chain component where the rest is trivial.
- **High** — significant impact (privileged action by unauthenticated
  user, sensitive PII exposure, auth bypass for non-admin).
- **Medium** — meaningful but bounded (IDOR on non-sensitive data, XSS in
  authenticated-only UI, info leak).
- **Low** — best-practice violation without immediate exploit path.

If you're tempted to bump a medium to a high, ask: would I bump it down if
I were the team's reviewer? If yes, leave it medium.

## CVSS vectors

Use CVSS 3.1 strings. Default to standard contextless versions:

- Web SQLi unauthenticated: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`
- IDOR authenticated: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- SSRF to cloud metadata: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
- Stored XSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

Adjust as the actual context requires (e.g. PR:H if admin-only).

## CWE tagging

At least one CWE per finding. Common ones:

| Issue | CWE |
|---|---|
| SQL injection | CWE-89 |
| OS command injection | CWE-78 |
| XSS | CWE-79 |
| SSRF | CWE-918 |
| Path traversal | CWE-22 |
| XXE | CWE-611 |
| Insecure deserialization | CWE-502 |
| Missing authn | CWE-306 |
| Missing authz | CWE-862 |
| IDOR/BOLA | CWE-639 |
| JWT alg=none | CWE-347 |
| Weak crypto | CWE-327 |
| Hardcoded credentials | CWE-798 |
| Race condition | CWE-362 |
| Mass assignment | CWE-915 |
| Open redirect | CWE-601 |
| SSTI | CWE-94 |

Use the SARIF-friendly format `CWE-89` (with the dash).

## Evidence section

Every confirmed finding has at least one evidence entry. Kinds:

- `http_trace` — full HTTP request and response from a DAST PoC.
- `code_excerpt` — the source code that contains the bug, with surrounding context.
- `oob_callback` — JSON dump of an OOB collector hit.
- `dependency_vuln_record` — relevant entry from `dependency_vulns` output.
- `secret_scan_match` — entry from `secret_scan` output (with the secret value redacted).
- `iac_scan_finding` — relevant entry from `iac_scan` output.

The evidence section references files in `/state/evidence/` that the
generator includes by reference (not by inline content — those files can
be large).

## Remediation section

Two failure modes here:

1. **Too generic.** "Use parameterized queries." Better: name the specific
   library function. "Replace `cursor.execute(f\"SELECT ... WHERE id = {id}\")`
   with `cursor.execute(\"SELECT ... WHERE id = %s\", (id,))`."

2. **Too prescriptive without context.** "Switch from JWT to opaque tokens."
   That's a major architectural change. Better: "Either (a) pin the
   algorithm by passing `algorithms=[\"RS256\"]` to `jwt.decode`, or (b)
   move to opaque tokens with server-side state. Option (a) is the smaller
   change."

When in doubt, list multiple options and name the trade-offs.

## Refuted hypotheses (audit trail)

The technical report includes a Refuted Hypotheses section listing every
hypothesis the validator declined to confirm, with its refutation reason.

Why: traceability. If a future scan or a human reviewer disagrees with
Lacuna, the refutation reasoning is preserved.

Format:

```markdown
### `hyp-xyz` (sqli) — by hunter-injection

**Location:** `api/db.py:42`
**Hunter's confidence:** 0.55

> The query at line 42 builds a SQL string with f-string interpolation of
> the `user_id` parameter from the URL.

**Refutation:** SQLAlchemy ORM is in use; `User.query.get(user_id)` is
parameterized by construction. The validator confirmed via `code_excerpt`
that no `.execute()` call with raw SQL exists in the path.
```

## Primitives section

After findings, list every primitive with its canonical attributes. The
chain-builder may not have composed all of them; that doesn't make them
less real as capabilities. Format from `primitive-extraction` skill.

## Chains section

After primitives, list every chain with full narrative_md. Same format the
chain-builder produces.

## Needs-human section

Hypotheses the validator could not conclusively confirm or refute after 4
rounds. Each entry includes:
- The hypothesis ID, shape, location.
- What the validator tried.
- What evidence is missing.
- What a human reviewer should examine.

If this section is empty, omit it.

## Anti-patterns

- **The "see the SARIF file" report.** SARIF is for machines. The technical
  report is for humans. Include the prose.
- **The wall of severity-1 noise.** If you find yourself listing 50 low-
  severity findings, group them. (E.g. "Missing security headers across N
  endpoints — see appendix A.")
- **The defensive caveat.** Don't write "this finding may or may not be
  exploitable depending on..." If the validator wasn't sure, it would be in
  `needs_human`, not in confirmed findings.
