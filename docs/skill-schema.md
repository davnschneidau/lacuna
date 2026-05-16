# Skill schema

The contract every file under `.claude/skills/<name>/SKILL.md` must
satisfy. `scripts/lint_docs.py` walks the skills directory and
validates each one against this schema; PRs that introduce a skill
without the required fields fail CI.

A skill is a *procedure* — a multi-step approach that one or more
agents may follow. It is not a tool (tools live in MCP servers) and
not an agent (agents live in `.claude/agents/`). The skill is
human-readable and agent-readable in the same document.

---

## Required frontmatter

```yaml
---
name: <kebab-case>
description: <one sentence, ≤ 200 chars>
when_to_use:
  - <imperative condition>
  - <imperative condition>
---
```

- **name** — kebab-case, matches the directory name
  (`.claude/skills/<name>/SKILL.md`). No spaces, no underscores.
- **description** — one sentence, ≤ 200 characters. Used by agents
  that scan for "is this skill relevant?" — be concrete about the
  triggering situation.
- **when_to_use** — list of imperative conditions describing the
  triggering situations. Each item should be specific enough that
  another agent could read it and decide "yes, this applies to my
  current task" or "no, it doesn't" without reading the body. At
  least one entry; typically 2–4.

## Required sections

In order:

1. `# <Title-Cased name>` (h1)
2. A motivation paragraph (1–3 sentences): why this skill exists,
   what failure mode it averts.
3. `## Procedure` (h2): the step-by-step walkthrough. Numbered
   list. Each step:
    - opens with an imperative verb;
    - cites the specific tools / KG queries / file artefacts it
      uses;
    - if the step has a non-obvious failure mode, names it.
4. `## Anti-patterns` (h2): the wrong ways to perform the procedure
   we have already seen agents reach for. Bullet list.

## Optional sections

- `## Rationale` — when the procedure is non-obvious or expensive,
  explain the trade-off.
- `## Examples` — concrete worked examples. The lint accepts
  markdown code fences or excerpts of agent transcripts.
- `## See also` — cross-references to other skills or to
  `docs/glossary.md` entries.

## Code blocks

Every fenced code block in a skill MUST declare a language. The
`scripts/lint_docs.py` doc-as-test pass refuses fenceless blocks
because they break the assumption that the agent can syntax-aware
parse them. Block-types that don't have a natural language tag use
`text`.

## Anti-patterns for the schema itself

- "I'll add the frontmatter later." — Lint refuses skills without
  it.
- "Description is two sentences and 400 chars." — Lint refuses;
  trim.
- "when_to_use says 'use when needed'." — Lint refuses; be
  specific. The point of the field is to short-circuit irrelevant
  invocations.
- "Procedure is a wall of prose." — Lint accepts but reviewers will
  refuse. Steps must be numbered list items.

## Worked example

See `.claude/skills/disprove-first/SKILL.md`. The frontmatter,
section structure, and anti-patterns block all conform.
