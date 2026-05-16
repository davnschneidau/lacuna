---
name: counterfactual-reasoning
description: Ask "what would have to be true for this NOT to be a vulnerability?" before confirming or refuting any hypothesis. Use during validation to prevent both over-confirmation and over-refutation.
when_to_use:
  - Validator is one round away from confirming or refuting a hypothesis.
  - Adversary is reviewing a finding under the disprove-first procedure.
  - A hunter is tempted to mark a hypothesis confirmed without a PoC.
---

# Counterfactual reasoning

The most common validator failure modes are:
1. **Over-confirmation**: "the code looks dangerous, so it must be vulnerable."
2. **Over-refutation**: "there's a check somewhere, so it must be safe."

Counterfactual reasoning disciplines both. Before writing any verdict, ask the
counterfactual question: **"What would have to be true for this hypothesis to
be wrong?"**

## When to use

- Before writing `confirmed` — ask the refutation counterfactual.
- Before writing `refuted` — ask the confirmation counterfactual.
- When the red/blue dialectic is stuck after 2 rounds.
- When evidence is mixed (some suggests safe, some suggests dangerous).

## The two counterfactuals

### Refutation counterfactual (before confirming)

Ask: **"If this is NOT a real vulnerability, what would explain the evidence?"**

Common refutation stories:
- The sanitizer is elsewhere (a middleware layer not yet read)
- The dangerous call is unreachable from any attacker-controlled entrypoint
- The framework transparently parameterizes the query
- The type system constrains the value before it reaches the sink
- The dangerous function is behind feature flag disabled in production
- The "user input" in question is actually a server-side enum, not free text

**How to discharge the counterfactual:**
For each plausible refutation story, test it:
1. Call `reachable_from(repo, entrypoint, target)` — is the sink reachable?
2. Call `data_flow_paths(repo, source_kind=..., sink_kind=...)` — is there an actual path?
3. Call `auth_surface(repo)` — what authentication guards this entrypoint?
4. `code_excerpt` the middleware stack around the route.

If you cannot discharge ALL refutation stories → downgrade to `needs_human`,
not `confirmed`.

### Confirmation counterfactual (before refuting)

Ask: **"If this IS a real vulnerability, what would the exploit look like?"**

Common confirmation stories:
- The check exists but only on one code path, not all paths
- The sanitizer can be bypassed (different encoding, null byte, length limit)
- The framework is mis-configured (e.g. disable_escaping=True)
- The guard was added after the vulnerable path (defensive coding around
  a known bug, but the original path still exists)
- Race condition: the check and the use are not atomic

**How to discharge the counterfactual:**
1. Call `function_change_history(repo, file, function)` — was a guard recently
   added (potentially incomplete)?
2. Call `test_coverage_for_endpoint(repo, route)` — is the guard tested for
   bypass cases, or only for the happy path?
3. If the guard is a regex: look for bypass payloads using the `interesting-input`
   skill.

If ANY confirmation story is plausible and you cannot eliminate it → do NOT
refute. Mark `needs_human` with a clear explanation of which story you
could not eliminate.

## The asymmetry rule

Confirmation and refutation are NOT symmetric risks:
- A **false negative** (missed vulnerability) = production compromise
- A **false positive** (false finding) = analyst time wasted

Err toward `needs_human` rather than either false outcome.

**Threshold:**
- Confirm only when ALL refutation stories are discharged.
- Refute only when ALL confirmation stories are discharged.
- `needs_human` for anything else.

## Worked example

Hypothesis: SQL injection in `search_users(query)` via `request.args.get("q")`.

**Before confirming:**
```text
Refutation story 1: Framework parameterizes queries automatically.
  → Read: code_excerpt(search_users). Uses raw string formatting. DISCHARGED.

Refutation story 2: Entrypoint requires admin auth.
  → Read: auth_surface. Route has @login_required but not @admin_required.
     Any logged-in user can reach it. DISCHARGED.

Refutation story 3: Sanitizer strips SQL metacharacters.
  → data_flow_paths shows path from request.args to cursor.execute with
     no sanitizer nodes. DISCHARGED.

All stories discharged → confirm.
```

**Before refuting (hypothetical different scenario):**
```text
Confirmation story: There's a bypass for the allowlist check.
  → The allowlist checks for "SELECT" but not "SeLeCt". Bypass exists.
    CANNOT DISCHARGE → needs_human.
```

## Output format

When using this skill, emit your reasoning inline before the verdict:

```text
Counterfactual check:
- Refutation story 1 [mitigation type]: [discharged/not discharged — evidence]
- Refutation story 2 [mitigation type]: [discharged/not discharged — evidence]
...
Verdict: confirmed | refuted | needs_human
Reason: [one sentence]
```
