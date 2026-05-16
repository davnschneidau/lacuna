---
name: disprove-first
description: Write the argument-AGAINST a finding before reading anything else. Forces the adversary to invert their default assumption from "this is probably a bug" to "this is probably wrong; prove me wrong."
when_to_use:
  - The adversary or chain-adversary agent is about to score a finding.
  - The validator wants to pre-bias a hypothesis as "high confidence."
  - Any time a confirmation is being added to the KG without an
    explicit refutation attempt on file.
---

# Disprove First

This is the single load-bearing skill of the adversary machinery.
The historic skeptic procedure (see `.claude/agents/skeptic.md`)
asked the reviewer to start by reading the finding and then "look for
counter-evidence." That ordering is wrong:

- The first sentence the reviewer reads is the validator's confirmation.
- That sentence anchors them.
- Every subsequent tool call is interpreted in light of that anchor.
- "Counter-evidence" becomes a search for a *specific* refutation rather
  than a search for *any* refutation.

The fix is to write the refutation FIRST, on paper, before reading the
finding's narrative or the validator's notes. Then go look for evidence
that supports the refutation. The reviewer's reasoning is bounded by
"what's the strongest argument this isn't a bug?" — exactly the angle
that an external reviewer (or an exploit-incentivised attacker) would
take.

## Procedure

### 1. Read ONLY the finding's title and bug class.

Do NOT read:

- The validator's `validator_summary`.
- The minimal_repro.
- The attached evidence narratives.
- Other adversary verdicts.

You may read:

- The CWE.
- The file:line.
- The severity.
- The repo name.

### 2. Write an argument_against in the form:

> "This finding is almost certainly a false positive because …
> Specifically I expect that:
>
> (a) the function is not reachable from any untrusted entry point;
> (b) there is a sanitizer X between the source and the sink that the
>     engine missed;
> (c) the test suite already asserts the safe behaviour;
> (d) the path was already patched in commit Y;
> (e) the precondition (auth state, config flag) the bug requires is
>     never met in production."
>
> The most plausible reasons in order of likelihood are: …

Write it in YOUR voice, as if you're a senior engineer arguing the
finding should be closed. Be specific — name the file, the sanitizer
you expect, the test name. If you can't be specific, your refutation
is weak and the finding probably stands.

### 3. Now go look for evidence.

For each item in your argument_against, run the corresponding tool:

| Argument                              | Tool                                |
|---------------------------------------|-------------------------------------|
| (a) Not reachable                     | `reachable_from`                    |
| (b) Sanitizer present                 | `code_excerpt`, `data_flow_paths`   |
| (c) Test asserts safe behaviour       | `test_assertions_for_function`      |
| (d) Recently patched                  | `function_change_history`           |
| (e) Precondition unmet                | `code_excerpt` on the call site     |

### 4. Resolve.

- If 2+ items in your argument_against are substantiated by evidence,
  the verdict is `refuted` (or `downgrade` if the finding is real but
  smaller than claimed).
- If 0 items are substantiated, the verdict is `confirmed`.
- If 1 item is substantiated and 1 is unclear, the verdict is
  `needs_human`.
- If you run out of budget, the verdict stays at `refute_pending` and
  the Stop hook flags the finding.

### 5. Write the argument_for as a steel-man.

Before saving the verdict, write the `argument_for` — the strongest
case FOR the finding being real. This is what the report will quote
when defending the finding to a reader. A confirmed verdict without
a written argument_for is worthless because the reader has to
reconstruct your reasoning.

## Anti-patterns

- "Skim everything, then write the verdict." — This is what the old
  skeptic did. Don't.
- "argument_against was generic." — If you wrote "could be a false
  positive," you didn't do the skill. Be specific.
- "Used 12 tool calls." — Stop at 6–8. After that the cost outweighs
  the calibration improvement; mark `needs_human` and move on.
- "Skipped because verdict was obvious." — The crash-forbids-refute
  rule is the only exception; for everything else, run the skill.
