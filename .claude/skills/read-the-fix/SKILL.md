---
name: read-the-fix
description: |
  How to read a security-relevant commit for bug-class essence, not
  site-level fix. The patch-archaeologist agent applies this; any agent
  reading git_history for security commits should too.
---

# Reading a Fix Like a Researcher

A security commit teaches you a bug class. The patch closed one site;
your job is to learn the bug class so you can find the other sites.

## What you're actually reading

A diff has three useful signals:

1. **Removed lines** (the dangerous pattern that existed before)
2. **Added lines** (the safety guard that closed it)
3. **The function/file context** (the code SHAPE this lives in)

## The four questions

For each security commit, answer in order:

### 1. What was the bug class?

Not "fixed XSS" — what specifically about the code shape made it XSS?

- User-controlled string flowing to an HTML render without escape?
- Template engine with `|safe` filter applied to attacker input?
- React `dangerouslySetInnerHTML` with non-sanitized prop?
- Server-side concatenation into JSON-as-HTML payload?

Each has different variants. The bug CLASS is the precise shape, not
the CWE label.

### 2. Is the fix at the right abstraction level?

Three levels:

- **Site-level:** fixed one specific use of the dangerous pattern.
  Example: added `escape()` around one variable in one template.
  → Variants exist. Search the codebase.

- **Function-level:** wrapped the dangerous function in a safer one.
  Example: replaced direct `eval(user_input)` with a parser function.
  → Variants are mostly closed within this codebase, but uses of the
  underlying `eval` elsewhere may survive.

- **Type-level:** changed types so the dangerous use is no longer
  possible. Example: introduced `SafeString` type that can only be
  constructed via escape().
  → Variants are eliminated; the type system enforces.

Most fixes are site-level. Most authors think they fixed the class.

### 3. Was the fix COMPLETE for its abstraction level?

Even at site-level, a fix can be incomplete:

- Fix added escape for `<` and `>` but missed `'` and `"`.
- Fix sanitized one input parameter but not another in the same handler.
- Fix added auth check but check is `if (user)` which is true even for
  anon users with empty session.
- Fix used regex blacklist where attacker can use the next character
  not in the blacklist.

When you see an incomplete fix, the variant space is *immediate* —
the same file, same function, may still be vulnerable on the OTHER
inputs the fix didn't address.

### 4. What did the author NOT notice?

This is the deepest question. The fix addresses what the author saw.
Vulnerability researchers ask: what's adjacent that they didn't see?

- Author fixed SQL injection by parameterizing the WHERE clause —
  did they parameterize the ORDER BY? (ORDER BY can't bind-param in
  most engines.)
- Author fixed path traversal by checking for `..` — did they check
  for `%2e%2e` after URL decode? For Unicode lookalikes?
- Author fixed deserialization by allowlist — does the allowlist
  cover gadgets via inheritance? Via interface implementations?

## Workflow

Given a commit SHA:

1. Run `patch_essence(commit_sha)`. Read its `essence_md`.
2. Apply the four questions in your head.
3. If site-level fix and `confidence >= 0.4`: run `propagate_pattern`
   with the generated rule. Each match is a candidate variant.
4. If incomplete fix: even without propagation, file a hypothesis on
   the same site for the missed sub-pattern.
5. If author missed adjacent surface: file separate hypotheses for the
   adjacent attack vectors.

## Anti-patterns

- Don't treat the fix's commit message as truth. "Fix CSRF" can mean
  many things; some of them are wrong.
- Don't trust that backports are correct. The fix in trunk may be
  complete; the backport to v1.x may be incomplete.
- Don't skip pre-release fixes. The exploitable variant may have been
  exploited before the fix shipped publicly.
