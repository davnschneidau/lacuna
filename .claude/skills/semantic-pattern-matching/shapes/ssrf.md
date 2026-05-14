---
shape: ssrf
title: Server-Side Request Forgery
---

# Server-Side Request Forgery

## Intent
Cause the server to issue an HTTP/URL request to an attacker-chosen target.

## Syntactic surface

What this usually looks like in code:

- `requests.get(url)`, `urllib.urlopen(url)`, `fetch(url)` where `url` originates from user input.
- `Image / file URL parameters (avatars, document import, OG preview).`
- `Webhook callbacks where URL is user-supplied.`
- `Server-side PDF / screenshot rendering of user-supplied URLs.`
- `URL parsers that handle redirects without re-validating the target.`

## Semantic signals

- **HIGH** — URL is taken verbatim from request, no allow-list, no scheme/host filter.
- **HIGH** — Service runs in cloud (AWS/GCP/Azure) — IMDS access enables credential theft.
- **HIGH** — Service has visibility to internal hosts (per service map / manifest trust_boundaries).
- **MEDIUM** — Scheme is restricted to http/https but host is not, and metadata services are not blocked.
- **MEDIUM** — Allow-list exists but uses string `.startsWith` / `endsWith` checks (bypassable).
- **LOW** — Request goes through a configured egress proxy that rejects non-public IPs.
- **REFUTING** — URL is built from a fixed allowlist mapping (e.g. user picks `provider_id`, server builds URL).
- **REFUTING** — URL validated by parsing then checking host against an allow-list with no redirects followed.

## Variants

- Basic SSRF — attacker fetches internal HTTP endpoint.
- Cloud metadata — attacker fetches 169.254.169.254 to steal IAM creds.
- Blind SSRF — response not returned, confirmed via OOB callback.
- Gopher / file:// SSRF — non-HTTP protocols may speak Redis/Memcached.
- Redirect-based — server fetches attacker URL that 302s to internal host.
- DNS rebinding — host resolves to public IP at validation, private IP at fetch.

## Calibration

Any server-side HTTP client called with a user-controlled URL is a strong hypothesis. Cloud metadata access (IMDSv1) is the single highest-impact pattern. Allow-lists by hostname suffix are nearly always bypassable (`evil.attacker.com` ends with `attacker.com`).
