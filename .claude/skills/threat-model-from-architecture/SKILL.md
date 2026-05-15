---
name: threat-model-from-architecture
description: Derive attacker-relevant threat scenarios directly from the application architecture (service map, IaC, trust boundaries). Use during Phase 1 reconnaissance to seed hunters with architecture-level threats before reading any source code.
---

# Threat model from architecture

This skill turns the application model into attacker scenarios *before* any
code is read. Architecture-level threats guide hunter prioritization: focus
hunters where the attack surface is widest, the data is most sensitive, and
the trust boundaries are thinnest.

## When to use

Call this skill immediately after `kg.write.application_model` completes. The
output is a list of architecture-level threat scenarios that each map to one
or more hunter shapes. Write each scenario as a `kg.write.observation` with
`affects_shapes` set to the relevant hunters.

## Procedure

### Step 1 — Map the trust topology

From the application model, extract:

```
Services × trust level:
  - Internet-facing services (level 0 — full attacker control)
  - Internal services reachable from internet-facing services (level 1)
  - Backend services / databases (level 2)
  - Admin/management planes (level 3)
```

Draw explicit edges: which service calls which, via what protocol, with what
authentication.

### Step 2 — Apply the attacker entry points

For each internet-facing service:
- What data does it accept? (file uploads, user content, API requests, webhooks)
- What backends does it call? (DBs, internal APIs, queues, caches)
- What credentials does it hold? (service accounts, API keys, JWT secrets)

For each internal service that is reachable from internet-facing services:
- Is it authenticated? (assume the internet-facing service is compromised)
- Does it have a different (higher) privilege level?
- Does it trust calls from the internet-facing service unconditionally?

### Step 3 — Generate threat scenarios

For each entry point and each data flow, generate a threat scenario using
the following template:

```
Threat: [Attacker action]
Entry:  [Service + endpoint]
Target: [Asset or behaviour]
Shape:  [hunter shape this maps to]
Why plausible: [one sentence]
```

Apply these heuristics:
- **Any service that accepts file uploads and calls another internal service**
  → SSRF, XXE, path traversal, zip-slip
- **Any service that constructs DB queries from user input**
  → injection (SQL, NoSQL, LDAP)
- **Any JWT-based auth between services**
  → JWT misuse (algorithm confusion, alg=none, JWKS SSRF)
- **Any service-to-service call without mTLS**
  → SSRF pivot, credential theft
- **Any admin plane reachable from non-admin code**
  → privilege escalation
- **Any queue/event bus consumed by multiple services**
  → event injection, deserialization RCE
- **IaC with IAM roles / service accounts**
  → over-permissioned roles, credential exposure in metadata

### Step 4 — Write observations

For each scenario, write:

```python
kg.write.observation(
    agent="<current-agent>",
    content="<threat scenario in 1-3 sentences>",
    affects_shapes=["<hunter-shape-1>", "<hunter-shape-2>"],
    confidence=0.6,
    source_type="architecture_analysis",
)
```

Use `affects_shapes` to ensure the right hunters receive the signal.

## Priority ordering

Rank threats by: (impact × reachability). Impact = data sensitivity.
Reachability = how many hops from the internet.

Highest priority threats:
1. Internet → internal unauthenticated service (reachability=1, impact=high)
2. Any RCE-capable deserialization in internet-facing service (impact=critical)
3. JWT secret exposure in multiple services (impact=critical)
4. Admin plane reachable from non-admin code (impact=high)

Lowest priority threats:
- Internal-only services with no internet-facing callers (unless pivot chain)

## Output format

Write one `kg.write.observation` per scenario, then emit a `<next-actions>`
block listing the hunters most primed by this analysis, in priority order.
