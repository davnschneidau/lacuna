---
shape: xss
title: Cross-Site Scripting
---

# Cross-Site Scripting

## Intent
Render untrusted input as HTML/JS in a browser context.

## Syntactic surface

What this usually looks like in code:

- `Server returns user-controlled value in HTML without escaping.`
- Template uses `|safe`, `{{!}}`, `mark_safe`, `Html.Raw`.
- JS sets `.innerHTML = userInput`.
- JS uses `document.write` / `dangerouslySetInnerHTML` (React).
- Vue `v-html`; Angular `bypassSecurityTrustHtml`.
- `Stored: input persisted then later rendered without escaping.`
- DOM XSS: client-side code uses `location.hash` / `location.search` in a sink.

## Semantic signals

- **HIGH** — Template explicitly opts out of escaping (e.g. `{{ x|safe }}`) and `x` is user-controlled.
- **HIGH** — innerHTML / dangerouslySetInnerHTML with a value from props/state derived from URL or fetch response.
- **MEDIUM** — Server response includes user input inside a `<script>` tag context — JSON-escape is not enough.
- **MEDIUM** — Cookie value rendered into a page without escaping (assuming attacker can set the cookie).
- **LOW** — Pattern matches but the rendering context is plain text and the framework auto-escapes by default.
- **REFUTING** — Framework auto-escapes (Jinja2, ERB, Razor, Vue/React default mode) and there is no explicit opt-out.
- **REFUTING** — Response Content-Type is JSON (not interpreted as HTML by browsers).
- **REFUTING** — CSP `script-src 'self' 'nonce-...'` set and the rendered context can't execute external scripts.

## Variants

- Reflected — value from the request appears in the response.
- Stored — value is persisted then later rendered.
- DOM — entirely client-side; server may be uninvolved.
- Mutation XSS (mXSS) — browser HTML parser mutates 'sanitized' content into executing code.

## Calibration

Most modern frameworks escape by default. The presence of `|safe` / `mark_safe` / `dangerouslySetInnerHTML` is a strong signal worth investigating. CSP can downgrade severity but rarely fully mitigate stored XSS.
