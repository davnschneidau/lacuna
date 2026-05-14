---
name: weird-machine
description: Think laterally about what computation each primitive enables beyond its intended use. Use during chain-construction whenever you have 2+ primitives and want to discover unintended compositions.
---

# The Weird Machine

A "weird machine" is unintended computation built from intended primitives.
Every bug that looked obvious in retrospect is one — but in the moment, the
finder saw a composition the developers didn't.

The chain-builder's default failure mode is **literal-mindedness**: SSRF is
treated as "the server fetches a URL," SQLi as "the attacker reads the DB,"
open redirect as "the user is sent to a bad page." These framings throw
away most of the primitive's actual computational power.

This skill is the antidote. For each primitive in your kit, ask the
unintended questions.

## The catalog of unintended computations

### SSRF (the server makes an outbound request)

Intended view: read internal HTTP services.

Unintended view:
- **DNS side-channel exfil.** The server resolves attacker-controlled
  hostnames before fetching. You can encode bytes into subdomains and
  observe them at an authoritative DNS server you control. No HTTP needed.
- **Cloud metadata.** AWS IMDSv1, GCP metadata, Azure metadata — instance
  credentials are one request away.
- **Protocol smuggling.** `gopher://` and `dict://` and (in some libraries)
  `ftp://` reach Redis, Memcached, MySQL, FastCGI as raw TCP. (Use the
  gopherus oracle.)
- **Internal network mapping.** Different response times for connect vs
  refused vs timeout = port-scan oracle.
- **TLS oracles.** Different error messages for cert-mismatch vs
  protocol-mismatch leak internal host configuration.
- **Cache poisoning.** If the SSRF target is a cache layer, you can plant
  responses for other users.

### XSS (you inject script into a page)

Intended view: steal cookies.

Unintended view:
- **Cookie is HttpOnly?** Use the XSS as a SAML/OAuth-callback hijack — you
  don't need the cookie, you need the user to do a thing while logged in.
- **CSP blocks inline?** Use a script-src whitelisted domain. CSP that
  allows `unpkg.com` allows any package's exfil.
- **Self-XSS only?** Combine with a CSRF-able profile-edit endpoint and
  you have a stored XSS at scale.
- **Stored XSS in admin panel?** That's RCE-equivalent if the admin can run
  arbitrary actions (most can).

### Open redirect

Intended view: phishing.

Unintended view:
- **OAuth `redirect_uri` smuggling.** If the redirect URI validation
  accepts your domain, you can steal authorization codes.
- **Email-link reputation laundering.** Your phishing email sends through
  a known-trusted domain. Email security gateways trust the domain.
- **Cookie scope abuse.** Redirect from `foo.example.com` to
  `evil.example.com` — host-only cookies aren't sent, but subdomain
  cookies might be (and they include session tokens in many setups).

### Cache header weirdness

Intended view: …none, usually overlooked.

Unintended view:
- **Auth-oracle.** Authenticated vs unauthenticated routes return different
  `Vary:` or `Cache-Control:` headers — a CDN logs you in or out.
- **Static-vs-dynamic confusion.** A path that looks static to the CDN
  (ends in `.js`) but is actually dynamic at origin — the response is
  cached at the edge with whoever requested it first. Account takeover by
  visiting a URL.
- **Web cache deception.** Append `/foo.css` to an authenticated URL and
  some setups serve the auth'd content as a "static asset," which is
  cached by the CDN.

### Logging

Intended view: …none. Logs are write-only.

Unintended view:
- **Log injection → log-search XSS.** Many SIEM front-ends render log
  lines as HTML.
- **Log4Shell-style template expansion.** Some logging libs interpret
  format strings (`${jndi:...}`, `${env:SECRET}`).
- **Pivot via support tools.** A support engineer searches the logs by your
  email — your log entry contains `<script>`-laden text — their browser
  runs it in the internal log viewer.

### Path traversal / file read

Intended view: read `/etc/passwd`.

Unintended view:
- **`/proc/self/environ`** leaks environment variables, often containing
  database credentials.
- **`/proc/self/fd/N`** reads open file descriptors — including the
  application's own log file, which may contain secrets it didn't intend
  to log.
- **Application-config files** beat `/etc/passwd` for impact: `.env`,
  `config.yaml`, `application.properties` — these have keys.
- **Source-code disclosure** of the running app. Now you can find more
  bugs offline.

### Race conditions

Intended view: double-spend.

Unintended view:
- **State-machine break.** Simultaneous calls to "step 2" and "step 3" of
  a flow may both succeed when the FSM only allows one at a time.
- **Toctou on filesystem.** Check that a path is safe, THEN read it — if
  attacker can win the race, the read happens against a different path.
- **Concurrent password reset.** Two reset tokens both valid simultaneously.

### Information leak

Intended view: nice-to-have, low severity.

Unintended view:
- **Server timing oracle.** Login response time depends on whether the
  user exists — user enumeration → password spray.
- **Error message diff.** "Invalid password" vs "user not found" enables
  enumeration. "JSON parse error at column 42" tells you the request body
  was parsed up to the auth header — auth was skipped.

## Procedure

When chain-building or reviewing a finding, for each primitive you have:

1. Write down the intended use (what the docs say it does).
2. Write down 3 unintended uses using the patterns above as inspiration.
3. For each unintended use, ask: does this app's other primitives compose
   with it?
4. If yes, write a `kg.write.weird_composition` entry.

## Worked example

Hypothesis bundle:
- prim-1: SSRF on `/admin/preview-url?u=...` (auth required as admin)
- prim-2: Stored XSS in product reviews (any user can post)

Literal reading: two unrelated bugs.

Weird-machine reading:
- prim-2 lets you store a payload that executes in the admin's browser
  when they review a complaint.
- That payload makes an authenticated request to `/admin/preview-url?u=
  http://internal-redis:6379/` via prim-1.
- prim-1's SSRF + gopher:// reaches Redis with the admin's auth.
- Redis CONFIG SET writes an SSH key.
- Chain: any user → RCE.

The composition is the bug. Neither primitive alone is critical. Both
together are.
