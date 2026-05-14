---
name: primitive-extraction
description: |
  How to derive attacker primitives from a confirmed finding. A primitive
  is a capability-with-prerequisites-and-effects. Primitives are the unit
  of composition for the chain-builder; their quality determines whether
  chains are discovered.
---

# Primitive extraction

A finding describes a vulnerability. A **primitive** describes the
*capability* the vulnerability gives to an attacker. Findings are read by
humans; primitives are reasoned over by the chain-builder.

## The shape of a primitive

```
name: short, action-oriented (verb-object)
description: 1-2 sentences in plain English
prerequisites: list of canonical states required to use this primitive
effects: list of canonical states produced by using this primitive
repos_involved: which services this primitive operates against
```

Canonical vocabulary matters. The chain-builder matches effects-to-prereqs
by string equality (with some normalization). If one validator writes
`"authenticated user"` and another writes `"valid session"`, the chain
won't compose. Use the vocabulary below.

## Canonical prerequisites

- `unauthenticated network access to <repo>` — attacker can send HTTP to it.
- `authenticated user account on <repo>` — attacker has any logged-in user.
- `authenticated admin account on <repo>` — attacker has an admin user.
- `valid CSRF token` — attacker has bypassed or obtained a CSRF token.
- `victim user visits attacker URL` — XSS / CSRF preconditions.
- `read access to queue <name>` — attacker can read messages from a queue.
- `write access to queue <name>` — attacker can write messages to a queue.
- `internal network access to <service>` — attacker has crossed a trust boundary.
- `attacker-controlled DNS record` — DNS-based attacks.
- `outbound HTTP from <repo>` — attacker can listen on an OOB callback.
- `physical/file access to <path>` — local file write.

## Canonical effects

- `read secret <name>` — attacker can read a named secret/credential.
- `read row <model>` — attacker can read database rows of a given model.
- `execute code in <repo>` — attacker can run arbitrary code in the service.
- `valid session as <role>` — attacker now has a session of that role.
  Use `valid session as <user-id>` for a specific account takeover.
- `exfiltrate via <channel>` — attacker can pull data out (HTTP, DNS, etc.).
- `internal network access to <service>` — attacker has gained internal visibility.
- `write row <model>` — attacker can create or modify rows.
- `modify config of <repo>` — attacker can alter runtime configuration.
- `bypass rate-limit on <endpoint>` — attacker can issue unbounded requests.
- `account takeover of <user-id>` — full control of a specific account.
- `denial of service of <repo>` — service rendered unavailable.
- `read full file <path>` — local file read.
- `write file <path>` — local file write.

Use placeholders generously: `<repo>`, `<service>`, `<model>`,
`<endpoint>` are part of the primitive's text. They don't have to be
filled in with concrete names if the finding is generic; the chain-builder
matches on prefix.

## Example: from finding to primitives

**Finding:** SSRF in `image-proxy` service. Attacker can cause the service
to fetch arbitrary URLs.

**Primitives:**

```
P1:
  name: SSRF via image-proxy URL parameter
  description: Image-proxy fetches attacker-supplied URL and returns body.
  prerequisites: ["unauthenticated network access to image-proxy"]
  effects: ["outbound HTTP from image-proxy",
             "read full file <attacker-fetched URL response>",
             "internal network access to <service> (via attacker URL)"]
  repos_involved: ["image-proxy"]
```

That one finding produces three effects, each of which becomes a usable
input for the chain-builder.

**Finding:** Hardcoded JWT signing secret in `auth-svc` source.

**Primitives:**

```
P2:
  name: Forge JWT for arbitrary user
  description: HMAC signing key is in source; any actor with read access to
    the repo or its container image can sign tokens for any user.
  prerequisites: ["read access to <auth-svc source or container image>"]
  effects: ["valid session as <role>", "valid session as <user-id>"]
  repos_involved: ["auth-svc"]
```

(Note: the prerequisite is unusual — usually a primitive's prereq is a
state another primitive can produce. Here we're saying: anything that gives
an attacker access to the source code chains into total account takeover.)

## Decomposition rules

A single finding can produce multiple primitives. Decompose by *effect*. If
the same vulnerability gives an attacker three different observable
capabilities (e.g. SSRF gives outbound HTTP + arbitrary URL read +
internal-service access), write three primitives.

Conversely, do not write multiple primitives that have the same effects and
prereqs — they would compose identically. Pick the most general framing.

## What NOT to do

- Don't write primitives for refuted hypotheses. They're not real capabilities.
- Don't write primitives whose prerequisites are "vulnerability X exists" —
  that's tautological. The prerequisite should be a state the attacker can
  achieve (network access, session, etc.).
- Don't conflate effects. "Read secret X" and "exfiltrate data" are different
  primitives — the first is a capability; the second is a channel.

## When to add primitives, when to skip

Skip primitive writing for:

- Best-practice findings without an exploit path (e.g. missing X-Frame-Options
  header on an API endpoint that doesn't return HTML).
- Findings that are pure ergonomic / code-smell flags from semgrep with no
  concrete attacker scenario.

Always add primitives for:

- Any finding rated medium or higher.
- Any finding where the validator wrote a concrete PoC.
- Any finding that produces a session, code execution, secret read, or
  data exfiltration. These are the high-value chain building blocks.
