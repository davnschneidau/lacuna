---
shape: race
title: Race conditions / TOCTOU
---

# Race conditions / TOCTOU

## Intent
Exploit non-atomic check-then-act sequences to bypass invariants.

## Syntactic surface

What this usually looks like in code:

- `Read balance → check sufficient → debit balance (without DB transaction).`
- Check coupon `used == false` → use coupon → mark used.
- `stat() file → check ownership → open(file).`
- `Rate-limit check then operation (without atomic increment).`
- `Free-trial check then account creation.`

## Semantic signals

- **HIGH** — Financial / quota / one-time-token flow with read-check-write pattern and no explicit `SELECT … FOR UPDATE` / `WITH LOCK` / advisory lock.
- **HIGH** — ORM `.get()` then `.save()` without transaction or optimistic locking.
- **MEDIUM** — Endpoint marks something used but doesn't guard against concurrent claims.
- **MEDIUM** — No idempotency-key support on side-effectful POST/PUT.
- **REFUTING** — Operation uses atomic DB primitives (UPDATE … WHERE balance >= X, INSERT … ON CONFLICT).
- **REFUTING** — Distributed lock (Redis SETNX, ZK, etc.) wraps the critical section.

## Variants

- Financial double-spend.
- Coupon / discount reuse.
- Permission grant before role assignment is persisted.
- Filesystem TOCTOU (rare in modern web stacks).

## Calibration

If you can imagine submitting the same request 100x in parallel producing 100 successful outcomes when there should be at most 1, it's a hypothesis. Validator confirms with concurrent PoC.
