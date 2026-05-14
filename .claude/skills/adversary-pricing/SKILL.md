---
name: adversary-pricing
description: |
  Would an actual attacker bother chaining this? Severity calibration that
  asks the economic question, not the theoretical one. Chain-builder uses
  it to prioritize; validator uses it to pick severity bands.
---

# Adversary Pricing

Not every theoretical bug is worth chaining. The chain-builder finds the
chain; this skill prices it.

## The question

For a candidate exploit chain, ask: would a real attacker with realistic
resources find this worthwhile?

The answer depends on five factors:

1. **Effort to build the exploit** (lower → more likely to be built)
2. **Reliability of the exploit** (higher → more attractive)
3. **Value extracted per use** (higher → more attractive)
4. **Visibility / detection risk** (lower → more attractive)
5. **Reusability across targets** (higher → more attractive)

## Tier 1 — built tomorrow

These attackers will build, no question:

- Single-request exploits. RCE in one HTTP call. SQLi that returns data
  in the response.
- High-value resource extraction. PII dumps. Credential databases.
  Source code archives. Payment data.
- Reusable across many targets. The same exploit hits 100 deployments.
- Self-contained. No human-in-the-loop required.

For Tier 1 candidates, severity should match the impact. CVSS 8.0+ is
where these typically land.

## Tier 2 — built for specific high-value targets

Requires custom work for each target:

- Multi-step exploits with timing or session-state dependencies
- Exploits requiring CSRF + XSS chain
- Privilege escalation that needs pre-existing low-priv access
- Exploits that require knowledge of internal IDs or schemas
- Exploits with reliability < 50%

These get built when the target is worth it. Banking app: yes. Random
SaaS: probably not.

For Tier 2, severity should reflect the gate. CVSS 5.0-7.5 typical.

## Tier 3 — theoretically possible, practically rare

Lots of moving parts and conditions:

- 4+ step chains with timing dependencies
- Exploits requiring the user to perform an unusual action (paste
  attacker-controlled text into a specific UI element while logged in)
- Exploits with high detection signal (DoS-style noisy probing required)
- Exploits where the payoff is small (single low-value record)

These get filed, but severity is below the "drop everything" threshold.
CVSS 3.0-5.0 typical, and prioritization shouldn't preempt Tier 1/2 work.

## Tier 4 — academic interest

You found a bug; an attacker wouldn't bother. Still worth reporting
(defense in depth), but don't generate noise.

- Self-DoS that only affects the attacker's own session
- Exploits requiring physical access in a context where physical access
  already grants root
- Exploits that require the attacker to already have admin
- Bugs in code paths that have never run in production

CVSS 0-3.

## Applying the discipline

When you have a confirmed finding ready to ship, ask:

1. **Effort score** (1-5): How many hours of work to build a reliable
   exploit, given the report and minimal_repro?
2. **Reliability score** (1-5): What % of exploit attempts succeed in
   the wild?
3. **Value score** (1-5): What does the attacker get per successful
   exploit?
4. **Stealth score** (1-5): How quickly do defenders notice?
5. **Reusability score** (1-5): How many similar targets does this hit?

Sum: 5-25.

- 20-25: Tier 1
- 15-19: Tier 2
- 10-14: Tier 3
- 5-9:   Tier 4

Map back to CVSS only after this. The CVSS score should follow the
pricing analysis, not lead it.

## Anti-patterns

- DON'T inflate severity to make a finding seem important. The skeptic
  catches this; trust gets lost.
- DON'T deflate severity to seem judicious. Tier 1 bugs are Tier 1
  even if you also found a flashier one.
- DON'T price by what the bug class is *capable* of. Price by what THIS
  exploit on THIS app does. A theoretical RCE in a 5-user internal admin
  panel is not the same as RCE in a public-facing service.
