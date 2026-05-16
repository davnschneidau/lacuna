---
name: chain-construction
description: |
  How the chain-builder composes primitives into attack paths. The procedure
  is graph search over the primitive ledger: effects of one primitive
  satisfy prerequisites of another. Narrative formatting and severity rules
  included.
when_to_use:
  - Chain-builder is running its composition pass over the primitive ledger.
  - A confirmed finding produced new primitives that may extend existing chains.
  - A report needs a narrative chain rather than a list of isolated findings.
---

# Chain construction

The chain-builder runs against a deliberately narrow context: just the
primitives, the application model summary, and the service map. No code,
no findings prose, no transcripts. This is by design — chain composition
is a graph problem, not a code-reading problem.

## The algorithm

1. **Build the graph.** For each primitive `B`, for each prerequisite `p`
   of `B`, for each primitive `A`, if any effect of `A` matches `p` (by
   canonical string match), add a directed edge `A → B`.

2. **Identify start nodes.** Primitives whose prerequisites are *external*
   — things an attacker can have at t=0:
   - `unauthenticated network access to <public-repo>`
   - `authenticated user account on <repo>` (any account, including their own)
   - `victim user visits attacker URL`
   - `outbound HTTP from <some repo>` (often comes from another primitive,
     but can be assumed at the public attack surface)

3. **Identify goal nodes.** Primitives whose effects belong to one of:
   - `rce` — `execute code in <repo>`, plus any further movement primitives
     from there.
   - `data-exfil` — `exfiltrate via <channel>` paired with `read row <model>`
     of sensitive type, or `read full file <path>` of secrets file.
   - `priv-esc` — `valid session as admin` (or any higher-priv role).
   - `account-takeover` — `valid session as <specific-user-id>`.
   - `financial-loss` — primitives that produce `transfer funds`,
     `issue refund`, `redeem coupon`.
   - `denial-of-service` — `denial of service of <repo>`.
   - `full-compromise` — combinations of `rce` with `priv-esc` against the
     core service.

4. **Search.** From every start node, find all paths to every goal node.
   Limit path length to 5 hops (longer chains are rarely actionable and
   usually indicate a primitive vocabulary mismatch).

5. **Score.** Each path gets a `combined_severity`:
   - `critical` — any RCE, full-compromise, admin account-takeover, large data exfil.
   - `high` — any non-admin account-takeover, financial-loss, multi-record data-exfil.
   - `medium` — DoS, single-user data-exfil without admin elevation.

6. **Narrate.** For each path, write the narrative (see below).

7. **Persist.** `kg.write.chain(...)` for each.

8. **Cleanup.** `kg.write.mark_primitive_explored` for every primitive,
   then `kg.write.set_exit_criterion(name="chain_search_exhausted", met=True)`.

## Edge matching rules

Strict equality is too strict. Use normalization:

- Lowercase before comparison.
- Substitute `<repo>`, `<service>`, etc. — a prereq with `<repo>` matches an
  effect referencing any specific repo.
- Trailing concrete identifiers (`<user-123>`) match the same primitive's
  placeholder version (`<user-id>`) as well as another instance.

Be liberal here. The chain-builder finding a candidate edge is the
*invitation* to write the narrative — the narrative will sort out whether
the composition makes practical sense.

## Narrative format

A chain narrative is a step-by-step walkthrough. Format:

```text
**Actor:** Unauthenticated external attacker.

**Step 1 — <name of primitive 1>**  ({repo})

The attacker {does something concrete} via {endpoint or surface}. The
{vulnerability} causes {outcome}.

*State of the world after step 1:* {what's now true that wasn't before}.

**Step 2 — <name of primitive 2>**  ({repo})

The attacker, using {state from step 1}, {does next thing}. The
{vulnerability} causes {outcome}.

*State of the world after step 2:* {...}

...

**Final outcome:** {explicit description of the goal — RCE on auth-svc, data
exfil of customer PII, admin account takeover, etc.}
```

The narrative is read by humans first (in the executive report) and may be
the most-read part of the entire scan output. Make it concrete, specific,
and free of jargon. Use proper names from the manifest (service names, etc.).

## Worked example

**Primitives in scope:**

- P1: SSRF in image-proxy (prereqs: net access to image-proxy;
  effects: outbound HTTP from image-proxy, internal net access to internal-api).
- P2: Hardcoded HMAC in internal-api (prereqs: read access to internal-api source;
  effects: forge any JWT). [Skipped here — source access prereq isn't reachable.]
- P3: SSRF→IMDS in internal-api (prereqs: net access to internal-api; effects:
  read AWS IAM credentials).
- P4: Admin endpoint in core-api without IP allow-list (prereqs:
  net access to core-api, valid session as admin; effects: execute code in core-api).
- P5: JWT signing key in shared KMS readable by AWS role X (prereqs: AWS IAM
  credentials with role X; effects: forge JWT as any user including admin).

**Chain candidates from start nodes:**

Start: `unauthenticated network access to image-proxy`.

- P1 → P3 (P1 effect "internal net access to internal-api" matches P3 prereq).
- P3 → P5 (effect "read AWS IAM" matches P5 prereq).
- P5 → P4 (effect "forge JWT as any user including admin" satisfies P4's
  "valid session as admin").
- P4 → goal: execute code in core-api → RCE.

**Chain:** P1 → P3 → P5 → P4, goal=rce, combined_severity=critical.

**Narrative:**

> **Actor:** Unauthenticated external attacker.
>
> **Step 1 — SSRF via image-proxy URL parameter** (image-proxy)
> The attacker sends `GET /proxy?url=http://internal-api.svc.cluster/...` to
> the public image-proxy. The proxy fetches the URL and returns the body. The
> attacker now has request/response access to internal-api.
>
> *State after step 1:* attacker can talk to internal-api as if from inside the cluster.
>
> **Step 2 — IMDS access from internal-api** (internal-api)
> The attacker uses the proxied request channel to make internal-api fetch
> `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
> The response contains AWS access key + secret + session token.
>
> *State after step 2:* attacker has AWS credentials for the EKS node role.
>
> **Step 3 — Read JWT signing key from KMS** (AWS)
> The attacker uses those credentials to call `aws kms decrypt` against the
> ciphertext stored in S3 alongside the application config. They obtain the
> JWT signing key.
>
> *State after step 3:* attacker can sign valid JWTs for any user.
>
> **Step 4 — Issue admin JWT, hit core-api admin endpoint** (core-api)
> The attacker forges a JWT with role=admin and calls
> `POST /admin/run-task` with a malicious shell command. The core-api
> executes the command.
>
> *Final outcome:* RCE in core-api with full admin privileges.

That's the level of detail to aim for.

## Anti-patterns

- **The "and a miracle occurs" chain.** If the narrative says "and somehow
  the attacker learns the secret," it's not a chain. Either find the
  primitive that produces that knowledge, or drop the chain.
- **The trivial chain.** Two primitives in the same repo that compose to
  the same outcome the simpler one already gives — write the simpler one as
  a single finding instead.
- **The unbounded chain.** More than 5 hops usually means the primitive
  vocabulary is too narrow. Re-examine the primitives.
