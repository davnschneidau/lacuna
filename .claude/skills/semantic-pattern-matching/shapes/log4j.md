---
shape: log4j
title: Log4j-style JNDI injection
---

# Log4j-style JNDI injection

## Intent
Inject `${jndi:ldap://...}` strings into logged values for RCE via Log4j or similar.

## Syntactic surface

What this usually looks like in code:

- `Log4j 2.x < 2.17.0 (CVE-2021-44228).`
- Custom logging that substitutes `${...}` interpolations on logged strings.
- `Spring's PropertyPlaceholderHelper used on user input.`

## Semantic signals

- **HIGH** — Application logs user-controlled values AND Log4j 2.x < 2.17.0 is on classpath.
- **HIGH** — Application uses StringSubstitutor / similar on user-controlled strings.
- **REFUTING** — Log4j >= 2.17.0 with default JNDI disable, OR logback in use.

## Variants

- Direct JNDI lookup via crafted log line.
- Nested / encoded variants to bypass naive filters.

## Calibration

Specific to Java stacks with the vulnerable Log4j range. Check dependency_graph for log4j-core 2.0–2.16.
