# ADR-0001 — Architecture Decision Record template

**Status.** Template. Copy to `NNNN-<short-slug>.md`, replace the
sections, and submit alongside the PR that implements the decision.

**Date.** YYYY-MM-DD.

**Deciders.** GitHub handles of the people who agreed.

## Context

The technical and organisational situation that motivated the
decision. Be concrete: cite file paths, function names, and prior
ADRs.

## Decision

A single declarative sentence stating what was chosen. Follow with
a short list of alternatives that were considered and rejected,
each with a one-line "why not."

## Consequences

What we get, what we give up, and what becomes harder. List the
*invariants* (see `docs/INVARIANTS.md`) the decision introduces or
modifies.

## Enforcement

Tests, lint scripts, hooks that prevent regression. If the answer
is "none", the decision is informational; if it's load-bearing,
something must enforce it before merge.

## Reversibility

How hard would it be to undo the decision? "Easy" (config flag),
"medium" (code change in N files), "hard" (data migration), or
"one-way" (schema change with no rollback story).
