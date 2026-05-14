---
shape: jwt
title: JWT Misuse
---

# JWT Misuse

## Intent
Forge or replay a JWT to act as another user.

## Syntactic surface

What this usually looks like in code:

- Verification with `algorithms=["none"]` or no algorithm pin.
- `jwt.decode(token, key, algorithms=["HS256", "RS256"])` — algorithm confusion.
- `Key passed as a public PEM but algorithm allowed to be HS256 (treats pub key as HMAC secret).`
- `Hardcoded HMAC secret.`
- `exp` not checked.
- Tokens reusable indefinitely (no `jti`, no revocation).

## Semantic signals

- **HIGH** — `alg=none` accepted by verification.
- **HIGH** — HMAC secret hardcoded in source / hardcoded in container env.
- **HIGH** — Multiple algorithms accepted in same `verify()` call — algorithm confusion possible.
- **MEDIUM** — No `exp` check — replay window unlimited.
- **MEDIUM** — Custom claim trusted without proof (e.g. `is_admin: true` claim accepted).
- **REFUTING** — Single algorithm pinned, asymmetric (RS256/ES256), `exp` checked, secret from KMS.

## Variants

- alg=none.
- HS/RS confusion.
- Weak HMAC secret (brute-forceable).
- JWKS endpoint manipulation (kid header).
- Expired-but-still-accepted tokens.

## Calibration

JWT bugs are common because the libraries expose all the rope. Anything other than 'pin one strong asymmetric algorithm, validate exp/aud/iss, rotate keys' deserves a hypothesis.
