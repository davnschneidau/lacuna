---
name: report-exec
description: |
  How to compose the executive report. Bottom-line-up-front; chains-first
  when present; non-technical attacker narrative; 3-5 prioritized fixes.
  Readers are non-technical stakeholders making resourcing decisions.
when_to_use:
  - You are about to write or regenerate the executive report.
  - A scan finished and the orchestrator is invoking the report pass.
  - You catch yourself writing CWE numbers in the exec narrative — re-read this skill.
---

# Executive report style

The executive report has one job: tell a busy reader, in the first
paragraph, how worried they should be and what they should do.

## Structure

```markdown
# Security Scan: {app_name}

[metadata block: date, mode, repos]

## Bottom Line
[1-2 sentences. The headline.]

## Risk Summary
[severity counts table]

## Composed Attack Chains   ← only if chains exist
[each chain as a numbered subsection]

## What an Attacker Could Do
[3 paragraphs of plain-English narrative]

## Recommended Priorities
[ordered list of 3-5 items]

## Methodology
[1-paragraph reminder of how Lacuna works]
```

## The bottom line

The bottom line answers: "should I be worried, and why?"

- If there are chains, the bottom line is about the worst chain.
- If there are no chains but there are critical findings, it's about those.
- If neither, it's about the overall posture being okay-with-caveats.

Three good bottom-line examples:

> This scan identified **two multi-step attack chains, the most severe being
> remote code execution as the core-api service account.** Chains compose
> lower-severity flaws into outcomes that individually-rated findings
> understate. Address them in the order shown below.

> This scan identified **3 critical and 7 high-severity findings.** No
> multi-step chains were composed within this scan's budget. Treat the
> individual findings as upper-bound risks pending manual chaining.

> **No critical or high-severity findings were identified.** This is a useful
> baseline; the scan still produced lower-severity findings worth reviewing
> before they age into risk.

Don't bury the lede. Don't say "this report contains the findings of..." —
the reader knows that. Say what's in it.

## Chains-first ordering

When chains exist, they go before individual findings in the report. The
reason: chains *are* the highest-impact items. A reader who reads only the
first page should see the worst-case outcome.

For each chain, include:
- The goal in plain English.
- The component primitives by name.
- A 2-3 paragraph attacker narrative that names actors and concrete actions.
- Critical: link to the technical report section for the chain's
  primitives (`chains.json` in the artifacts has machine-readable form).

## Attacker narrative

This is the most important section after the bottom line. Write it as a
short story. Be concrete. Use proper service names from the manifest.

Bad attacker narrative:

> A malicious actor could potentially exploit vulnerabilities in the
> application to gain unauthorized access to sensitive data or systems.

Good attacker narrative:

> An attacker who knows nothing about your infrastructure can:
>
> 1. Visit `https://app.example.com/proxy?url=...` — the image-proxy service
>    accepts any URL.
> 2. Use that to reach the internal-api service from the public internet,
>    bypassing your network boundary.
> 3. From there, request the AWS metadata endpoint and steal the EC2
>    instance's IAM credentials.
> 4. Use those credentials to read the JWT signing key from your KMS.
> 5. Forge a JWT claiming admin role.
> 6. Hit the `core-api` admin endpoint with a malicious command. Now they
>    are running code in your core service as admin.
>
> Each step on its own would be rated medium-severity. Combined, this is a
> path from "stranger on the internet" to "admin-level RCE."

That last sentence is the key — make the *combination* tangible.

## Priorities

3 to 5 items. Each item:

- Has a clear, action-oriented title.
- Has a one-sentence rationale.
- Cites at least one finding ID or chain ID for traceability.

Order: chain-breakers first (cheapest link in worst chain), then critical
findings, then highest-impact medium findings.

Bad priority:

> 1. Improve security controls across the codebase.

Good priority:

> 1. **Add a hostname allow-list to the image-proxy URL parameter** (chain-1).
>    The single change that breaks all three composed chains. Cheapest
>    intervention for the highest impact.

## Tone

- Direct. No "we believe" or "it appears that." Either Lacuna found
  evidence, or it didn't.
- Concrete. Name services, name endpoints, name files.
- Non-defensive. Don't soften findings to make them palatable. If a critical
  is critical, say so.
- Brief. The executive report should fit in a single 1500-word read.

## Anti-patterns

- **The catalog-in-prose.** Don't restate every finding from the technical
  report in narrative form. Refer the reader to the technical report.
- **The hedge.** Avoid "may," "could potentially," "in some cases."
  Lacuna *confirmed* findings via the validator. Say "is," "does," "allows."
- **The framework-bashing.** Don't blame the framework. The finding is in
  your code's use of it.

The executive report is a tool for action. Every sentence should help a
reader either understand the risk or decide on the next step.
