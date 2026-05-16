# ADR-0003 — Adversary defaults to `refute_pending`

**Status.** Accepted.

**Date.** 2026-05-16.

**Deciders.** lacuna-maintainers.

## Context

The historic *skeptic* agent's default verdict was `confirmed`, with
`refuted` reserved for "concrete counter-evidence". In practice
that gave validators a free pass on every finding the skeptic
couldn't disprove within its Haiku token budget. The skeptic
became a rubber stamp: it emitted `event_log` rows but never
actually flipped a verdict, the report's "Skeptic Reviews" section
was permanently empty, and the adversarial sweep had no enforcement
at the Stop hook.

## Decision

Introduce a new agent (`adversary`) whose default verdict is
`refute_pending`. Every confirmed finding MUST receive at least one
adversary verdict before the orchestrator can finish, enforced by
the Stop hook. Two-adversary mode adds an independent `adversary-b`;
disagreement promotes the finding to `needs_human` regardless of
which adversary was "right." A separate `chain-adversary` agent
reviews composed chains under the same regime; chain verdicts are
recorded in `chain_adversary_verdicts` and surfaced in the report,
but the Stop hook gate applies to *findings*, not chains.

The disprove-first skill (`.claude/skills/disprove-first/`) is the
operational ritual: write the argument-against in writing before
reading the finding's narrative, so the reasoning is bounded by
"what's the strongest case this isn't a bug?" rather than "find me
something wrong with this otherwise-confirmed finding."

## Consequences

**We gain.** Findings now defend themselves. The reporter renders
verdicts with glyphs (`[\u2713]` confirmed, `[\u2717]` refuted,
`[?]` needs_human, etc.) so analysts immediately see the
adversarial outcome. The SARIF emitter exposes
`lacuna_adversary_verdict` so downstream issue trackers can filter
by it. A *refuted appendix* surfaces the validator-vs-adversary
disagreements that the historic skeptic swallowed.

**We give up.** Haiku token cost: each finding now costs one
adversary call (sometimes two). Acceptable; Haiku is cheap relative
to the cost of shipping a false positive.

**Becomes harder.** Hand-written test fixtures must remember to
record an adversary verdict if they want the Stop hook to allow the
test scan to finish. The test helper `_seed_finding` documents this.

## Enforcement

- `tests/test_adversary.py` (all 11 tests).
- `lacuna.kg.client.KG.findings_missing_adversary_verdict`.
- `lacuna.hooks.stop_continuation` (gate).
- `lacuna.reports.generator._collect_adversary_verdicts` (glyphs).
- `lacuna.reports.generator._collect_refuted_findings` (appendix).
- `lacuna.reports.sarif_emitter._summarize_verdicts` (SARIF property).

## Reversibility

Medium. The `skeptic` agent file is retained for back-compat with
external pipelines that name it explicitly. Reverting would mean
re-routing the orchestrator's review step to the skeptic,
deleting the Stop hook gate, and accepting the calibration
regression.
