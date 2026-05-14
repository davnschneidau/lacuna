---
name: semantic-pattern-matching
description: |
  How to recognize vulnerability shapes that go beyond surface syntax. A
  "shape" is not a regex; it's an intent-plus-context pattern. This skill
  defines the shapes Lacuna hunts and the syntactic vs semantic signals that
  distinguish a real instance from a false positive.
---

# Semantic pattern matching

A regex scanner says "you wrote `eval(`, that's bad." A hunter says "you
wrote `eval(` on a string assembled from a request header you trust because
auth middleware verified it, but the middleware only checks the JWT
signature, not the claim values, which means an attacker who can issue
their own valid JWT (any authenticated user) controls that header." That's
the difference.

A **shape** has four parts:

1. **Intent.** What the code is *trying* to do.
2. **Syntactic surface.** What it usually looks like.
3. **Semantic signals.** Whether this instance is real or safe.
4. **Confidence calibration.** When to lean high, when to lean low.

The `shapes/` subdirectory has one file per shape Lacuna hunts. Read the
relevant ones at the start of each hunter's run.

## Index of shapes

- `shapes/sqli.md` — SQL injection variants
- `shapes/xss.md` — reflected, stored, DOM XSS
- `shapes/ssrf.md` — server-side request forgery
- `shapes/ssti.md` — server-side template injection
- `shapes/deserialize.md` — unsafe deserialization
- `shapes/idor.md` — broken object level authorization
- `shapes/jwt.md` — JWT-specific misuse
- `shapes/race.md` — TOCTOU and race conditions
- `shapes/mass-assignment.md` — overposting / mass assignment
- `shapes/open-redirect.md` — open redirects (chain enabler)
- `shapes/log4j.md` — Log4j-style JNDI lookup injection
- `shapes/path-traversal.md` — directory traversal in file APIs

## Calibration heuristics

Across all shapes:

- **High confidence (>= 0.7)**: source is named, sink is named, no obvious
  mitigation, and the framework/library is known not to handle this by default.
- **Medium confidence (0.4 - 0.7)**: source and sink are named, but there's
  *something* in the path (a sanitizer, a typed binding, a sandbox) that
  might be sufficient — the validator should decide.
- **Low confidence (0.2 - 0.4)**: pattern matches but key context is missing
  (you don't know if the source is actually reachable, or the sink is
  actually invoked).
- **Below 0.2**: don't write a hypothesis. Form a stronger one or move on.

A hunter that produces nothing but 0.9 hypotheses is wrong about something.
A hunter that produces nothing but 0.3 hypotheses is being too cautious.
Aim for a healthy spread.
