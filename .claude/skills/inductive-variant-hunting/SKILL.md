---
name: inductive-variant-hunting
description: After confirming one instance of a bug class, generate a propagation rule and systematically hunt for all sibling instances across the codebase. Use immediately after validator confirms a finding.
when_to_use:
  - Validator has just promoted a hypothesis to a confirmed finding.
  - The variant-hunter agent has been dispatched and needs the propagation procedure.
  - You suspect a bug class (not a single bug) and want to enumerate sibling sites.
---

# Inductive variant hunting

One confirmed bug is evidence of a pattern, not just a site. This skill
converts a single confirmed finding into a generalised propagation rule and
then runs that rule across the entire codebase to surface variants.

The empirical multiplier on real codebases: 1.5–4× variants per confirmed
parent. Most security reviews miss variants because they stop after finding
the first instance.

## When to use

Call this skill when:
- The validator has written a `confirmed` verdict for any finding.
- You are the `variant-hunter` agent.
- You want to extend the hunting surface beyond the original hypothesis.

## Procedure

### Step 1 — Extract the bug essence

From the confirmed finding, extract exactly three things:

```text
SOURCE:    What is the attacker-controlled input? (parameter name, type, path)
SINK:      What is the dangerous function/method/call site?
MISSING:   What sanitizer/check/guard is absent?
```

Example:
```text
SOURCE:    request.args.get("filename") — user-supplied string
SINK:      os.path.join(upload_dir, filename) + open(path, "rb")
MISSING:   Path traversal check (no normalization, no prefix assertion)
```

### Step 2 — Generalise to a propagation rule

Abstract the site-specific details into a language-level pattern:

```text
Rule: Any call to os.path.join() where one argument flows from
      request.{args,form,json,files} without intermediate normalization
      (Path.resolve(), os.path.abspath(), prefix check) is a candidate.
```

The rule should:
- Be specific enough to have a low FP rate (< 30%)
- Be general enough to match 2+ sites in a typical codebase
- Express the *absence* of a guard, not just the presence of the sink

### Step 3 — Run the rule

Call `propagate_pattern(repo, rule_description)` or express the rule as a
custom semgrep pattern via `custom_semgrep_scan(repo, rule)`.

For pattern construction, use these templates by bug class:

**Path traversal:**
```yaml
pattern: os.path.join($BASE, $USER_INPUT)
```
with taint source = HTTP request parameters.

**SQL injection:**
```yaml
pattern-either:
  - pattern: $DB.execute(f"... {$USER_INPUT} ...")
  - pattern: $DB.execute("..." + $USER_INPUT + "...")
```

**Deserialization:**
```yaml
pattern: pickle.loads($USER_INPUT)
```

**SSRF:**
```yaml
pattern: requests.$METHOD($USER_INPUT)
```
where USER_INPUT flows from request parameters.

### Step 4 — Triage results

For each match returned:

1. Call `code_excerpt(repo, file, line, context=10)` to read the surrounding code.
2. Apply the same three-element test: SOURCE present? SINK present? GUARD absent?
3. If all three hold → emit `kg.write.hypothesis(...)` with:
   - `parent_finding_id` = the confirmed finding's ID
   - `confidence` = 0.65 (variants are priors, not proofs)
   - `shape` = same as parent
   - `description` = "Variant of [parent ID]: [specific difference]"

### Step 5 — Link to parent

After writing hypotheses, write a variant link for each:
```python
kg.write.variant_link(child_hyp_id=..., parent_finding_id=...)
```

Hard cap: max 30 variants per parent finding to prevent runaway.

## Quality controls

- Never emit a hypothesis for a match where the guard *is* present
  but in a different form (e.g. allowlist check is 3 lines earlier).
- If all matches have guards → emit `kg.write.observation(content="Pattern
  X is consistently guarded across all N sites — no variants found")`
  and stop.
- If > 30 matches, triage the top-30 by reachability (prefer entrypoints
  reachable from the internet over internal-only paths).

## Example output block

```xml
<next-actions>
Variant hunt complete for finding fnd-abc:
- Propagation rule: os.path.join with user-supplied arg, no normalization
- Matches: 7 sites across 3 files
- Hypotheses written: 5 (2 had allowlist checks present, excluded)
- Linked as variants of fnd-abc
Confidence: 0.65 each. Validator should confirm top-2 first.
</next-actions>
```
