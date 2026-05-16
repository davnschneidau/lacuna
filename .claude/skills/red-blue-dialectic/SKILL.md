---
name: red-blue-dialectic
description: |
  How the validator adjudicates a hypothesis: by writing both the strongest
  exploit (Red) and the strongest refutation (Blue) for each round, then
  reconciling. Up to 4 rounds. Between rounds, summarize-then-forget via
  agent_notes to keep context lean.
when_to_use:
  - Validator opens a hypothesis and starts the adjudication loop.
  - A hypothesis was bounced back as needs_human and you are deciding whether to retry.
  - You are about to confirm a hypothesis after only one round — slow down and run the dialectic.
---

# Red/blue dialectic

A hypothesis is not a finding. It's a claim that needs adversarial review.
The validator's job is to *deserve* its verdict — confirm or refute — by
writing the strongest argument for each side and choosing between them.

This is the same technique used by good penetration testers in pair review,
formalized into a procedure.

## The structure of a round

Each round has three parts. Each part is short — caveman style.

### Red

Write the strongest possible exploit narrative for the hypothesis as stated.
You are the attacker. You have:

- Whatever access the hypothesis's attacker_scenario implies.
- Full knowledge of the codebase (you have read access to the recon tools).

Spell out:
1. The starting state of the world (what does the attacker know? what credentials?).
2. The specific request, payload, or code path.
3. The specific code that is exploited — by file:line.
4. The observable outcome (what does the attacker see? what changes server-side?).

Use technical language. Don't hedge. If you can't write a concrete exploit,
that's information for the reconcile step.

### Blue

Now you are the defender. Same code, opposite stance. Write the strongest
refutation. Possible angles:

- **Existing mitigation in the path** — sanitizer, validator, type binding,
  framework feature.
- **Source not actually reachable** — the route requires auth that the
  attacker scenario didn't account for, or it's mounted on an internal-only
  port.
- **Sink not actually invoked** — code path requires a flag that's never
  set in production.
- **Framework default behavior** — the supposed vulnerability is already
  handled by the framework (e.g. Django CSRF middleware, ORM parameterization).
- **Class of victim doesn't exist** — the supposed XSS is only triggerable
  by the same user (self-XSS), or the target endpoint is only callable by
  admins.

If your refutation is weaker than red — say so. "Blue: I can't find a
mitigation. Closest is X, but it doesn't apply because Y." That's also useful.

### Reconcile

Compare red and blue. One of:

- **Red wins decisively.** You have a concrete exploit; blue's refutations
  are all answered. Move to confirm.
- **Blue wins decisively.** Red's exploit is blocked by a specific named
  mitigation; you understand the mitigation; it covers all the variants you
  considered. Move to refute.
- **Ambiguous.** Red has a partial exploit; blue has a partial refutation;
  more evidence is needed. Run another round (with new evidence gathering)
  or, if already at round 4, mark `needs_human`.

## Between rounds: summarize-then-forget

After each round, write a brief note (the validator-specific
agent_notes path):

```python
kg.memory.write(
  path="/memory/agent_notes/validator/<hypothesis_id>.md",
  content="""
  Round 1: Red found {brief}. Blue found {brief}. Reconcile: ambiguous because {why}.
  Round 2 plan: {specific next step — fetch this evidence, send this request, read this code}.
  """,
)
```

At the start of the next round, read just that note (not the previous
round's full reasoning). This keeps your context lean across the four
rounds.

## Evidence-gathering between rounds

When red/blue is ambiguous, you have these tools to gain evidence:

- `code_excerpt` — pull more lines around the relevant location.
- `ast_query` — query the AST for related call sites (e.g. find every caller
  of this function).
- `taint_paths` — semgrep taint analysis for additional source-sink paths.
- `auth_surface` / `authz_checks` — re-check what middleware applies.
- `entrypoints` — confirm whether the endpoint is mounted as you assumed.
- `service_map` — check what trust boundary the service sits behind.

If DAST is enabled:

- `http_request` — execute the PoC and observe the response.
- `oob_callback_register` + `fuzz_param` + `oob_callback_poll` — for blind
  confirmation (SSRF, blind SQLi, log4j, etc.).
- `auth_login` — log in to test the endpoint as the role the hypothesis assumes.

## Stopping criteria

- **Stop on confirm.** Write finding, primitives, evidence. Update hypothesis.
- **Stop on refute.** Update hypothesis with refutation_reason citing specific code.
- **Stop on needs_human after round 4.** State explicitly what you tried,
  what evidence is missing, and what a human reviewer should examine.

## Example round (compressed for the skill — your actual rounds will be longer)

> **Hypothesis hyp-abc:** SSRF in image-proxy service at `proxy/handler.py:64`.
> Source: `request.args["url"]`. Sink: `requests.get(url)`. No allow-list visible.
>
> **Round 1 — Red:**
> Attacker sends `GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
> `handler.py:64` passes the URL straight to `requests.get`. Response body is
> returned to the attacker via `.content`. AWS instance metadata service returns
> IAM credentials. Attacker exfils them.
>
> **Round 1 — Blue:**
> Refutation attempt 1 — is there a scheme filter? `handler.py:60` calls
> `urlparse(url)` but only checks `.scheme in {"http", "https"}`. No host filter.
> Refutation attempt 2 — is there an egress proxy that blocks RFC1918? Check
> `Dockerfile` and `helm/values.yaml` — `HTTP_PROXY=corporate-proxy:3128`. The
> corporate proxy *might* block this. Cannot confirm without testing.
>
> **Reconcile:** ambiguous. The corporate proxy may or may not block 169.254.
> Need DAST evidence.
>
> **Round 2 evidence-gather:** Run `lacuna-dast.http_request` against the proxy
> endpoint with `url=http://169.254.169.254/latest/meta-data/`. Observe response.
>
> **Round 2 — Red:** PoC returned `HTTP 200` with body containing AMI ID,
> region, availability zone (evidence at /state/evidence/dast-http-xyz/).
> Corporate proxy did NOT block.
>
> **Round 2 — Blue:** No remaining refutation. The mitigation I hypothesized
> doesn't exist.
>
> **Reconcile:** Red wins. Confirm.
