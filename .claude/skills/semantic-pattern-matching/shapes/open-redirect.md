---
shape: open-redirect
title: Open Redirect
---

# Open Redirect

## Intent
Redirect a victim to an attacker-controlled URL via a trusted-domain link.

## Syntactic surface

What this usually looks like in code:

- `return redirect(request.args["next"])`.
- `res.redirect(req.query.url)`.
- Login flows with `?return_to=` parameter.
- `OAuth callback URLs not validated against the registered redirect_uri.`

## Semantic signals

- **HIGH** — Redirect target taken from request with no validation.
- **MEDIUM** — Validation uses `.startsWith("https://yourdomain.com")` (bypassable via `https://yourdomain.com.evil.com`).
- **MEDIUM** — Validation strips scheme but accepts protocol-relative `//evil.com`.
- **REFUTING** — Redirect target is from an allow-list of paths (relative URLs only).
- **REFUTING** — Target validated by parsing then comparing host against an exact allow-list.

## Variants

- Reflected open redirect.
- OAuth redirect_uri bypass (chain enabler — pair with CSRF for token theft).
- JS-rendered open redirect (location.href = userValue).

## Calibration

Open redirects are low-severity alone, high-severity as chain enablers. ALWAYS surface them as primitives for chain composition.
