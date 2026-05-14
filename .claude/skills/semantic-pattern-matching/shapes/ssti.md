---
shape: ssti
title: Server-Side Template Injection
---

# Server-Side Template Injection

## Intent
Inject template directives that are evaluated server-side.

## Syntactic surface

What this usually looks like in code:

- Jinja2 `render_template_string(user_input)`.
- Flask `flash(user_input)` where template renders it without `|escape` (less common).
- `Twig / Smarty / Velocity / Freemarker template strings built from user input.`
- `Server-rendered ERB / Slim / Haml with user-controlled string templates.`
- `Email body templating from user-provided subjects.`

## Semantic signals

- **HIGH** — `render_template_string` / `eval_template` with a string that includes user input.
- **HIGH** — Template name itself is user-controlled (path traversal into template injection).
- **MEDIUM** — User input feeds into a string later passed to template-rendering.
- **REFUTING** — User input is only ever passed as a *variable* to a static template (the normal case).
- **REFUTING** — Template engine runs in a sandbox with no `__class__` / `eval` access.

## Variants

- Jinja2 `{{ ''.__class__.__mro__[1].__subclasses__() }}` → RCE.
- Java EL / SpEL `${T(java.lang.Runtime).getRuntime().exec(...)}`.
- Velocity `#set($x = '') $x.class.forName(...)`.

## Calibration

SSTI is high-impact and uncommon. Most apps render static templates with dynamic variables. The bug is rendering a *template* that came from a user.
