#!/usr/bin/env python3
"""Validate agent definitions against the contract in docs/skill-schema.md.

Walks ``.claude/agents/*.md`` and asserts each agent file:

1. Has YAML frontmatter delimited by ``---`` lines at the very top.
2. The frontmatter contains the required keys: ``name``,
   ``description``, ``model``. Optional: ``tools``, ``skills``.
3. ``name`` matches the filename stem (no surprises when the
   orchestrator routes by name).
4. ``description`` is <= 400 characters once whitespace is collapsed --
   long enough to describe the agent, short enough that the routing
   layer can fit it in the context budget.
5. ``model`` is one of the documented LACUNA_MODEL_* env var
   interpolations (``${LACUNA_MODEL_HAIKU:-...}`` etc.) -- operators
   need a single knob to swap model tiers.
6. If ``tools`` is present, every entry starts with one of the
   permitted prefixes (``mcp__lacuna-recon__``, ``mcp__lacuna-kg__``,
   ``mcp__lacuna-dast__``, ``Read``, ``Glob``, ``Grep``, ``Bash``,
   ``Task``).
7. The agent's name appears in ``.claude/topology.yaml`` (invariant
   INV-008).

Run from CI on every PR:

    python scripts/lint_agents.py

Exit codes:
    0 -- every agent passes
    1 -- at least one agent violates the contract
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"
TOPOLOGY = REPO_ROOT / ".claude" / "topology.yaml"

REQUIRED_FRONTMATTER = ("name", "description", "model")
ALLOWED_TOOL_PREFIXES = (
    "mcp__lacuna-recon__",
    "mcp__lacuna-kg__",
    "mcp__lacuna-dast__",
    "Read",
    "Glob",
    "Grep",
    "Bash",
    "Task",
    "WebFetch",
    "WebSearch",
)
MODEL_RE = re.compile(
    r"\$\{LACUNA_MODEL_(?:OPUS|SONNET|HAIKU):-[A-Za-z0-9.-]+\}",
)
MAX_DESCRIPTION_CHARS = 400


def _parse_frontmatter(text: str) -> tuple[dict, list[str]]:
    """Use PyYAML for the frontmatter so block scalars (``description: |``),
    sequences (``tools:``, ``skills:``), and embedded colons in
    ``${VAR:-default}`` model strings parse correctly.
    """
    if not text.startswith("---"):
        return {}, ["missing leading '---' frontmatter delimiter"]
    end = text.find("\n---", 4)
    if end == -1:
        return {}, ["missing trailing '---' frontmatter delimiter"]
    raw = text[4:end]
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        return {}, [f"frontmatter is not valid YAML: {exc}"]
    if not isinstance(data, dict):
        return {}, ["frontmatter must be a mapping at the top level"]
    return data, []


def _load_topology() -> set[str]:
    if not TOPOLOGY.exists():
        return set()
    doc = yaml.safe_load(TOPOLOGY.read_text(encoding="utf-8")) or {}
    out: set[str] = set()
    for cat in ("shared", "sast_only", "dast_only", "either"):
        for name in doc.get(cat, []) or []:
            out.add(name)
    return out


def _validate(path: Path, topology: set[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    data, errors = _parse_frontmatter(text)
    if errors:
        return errors
    out: list[str] = []
    for required in REQUIRED_FRONTMATTER:
        if required not in data:
            out.append(f"missing required frontmatter key {required!r}")
    name = data.get("name", "")
    if name and name != path.stem:
        out.append(
            f"frontmatter name {name!r} does not match filename "
            f"{path.stem!r}",
        )
    description = data.get("description", "")
    if isinstance(description, str):
        collapsed = " ".join(description.split())
        if len(collapsed) > MAX_DESCRIPTION_CHARS:
            out.append(
                f"description is {len(collapsed)} characters "
                f"(> {MAX_DESCRIPTION_CHARS}); shorten or move detail "
                f"to the body",
            )
    model = data.get("model", "")
    if isinstance(model, str) and model and not MODEL_RE.fullmatch(model):
        out.append(
            f"model {model!r} does not match the "
            f"${{LACUNA_MODEL_TIER:-default}} pattern",
        )
    tools = data.get("tools", []) or []
    if isinstance(tools, list):
        for t in tools:
            if not isinstance(t, str):
                continue
            if not t.startswith(ALLOWED_TOOL_PREFIXES):
                out.append(
                    f"tool {t!r} is not under an allowed prefix "
                    f"({sorted(ALLOWED_TOOL_PREFIXES)})",
                )
    if name and topology and name not in topology:
        out.append(
            f"agent {name!r} is not classified in topology.yaml "
            f"(add to one of: shared / sast_only / dast_only / either)",
        )
    return out


def main() -> int:
    if not AGENTS_DIR.exists():
        print(f"ERROR: {AGENTS_DIR} missing", file=sys.stderr)
        return 1
    topology = _load_topology()
    failures: dict[str, list[str]] = {}
    count = 0
    for p in sorted(AGENTS_DIR.glob("*.md")):
        count += 1
        errs = _validate(p, topology)
        if errs:
            failures[str(p.relative_to(REPO_ROOT))] = errs
    if failures:
        print("FAIL: agent lint found problems:", file=sys.stderr)
        for path, errs in failures.items():
            print(f"  {path}:", file=sys.stderr)
            for e in errs:
                print(f"    - {e}", file=sys.stderr)
        return 1
    print(f"OK: {count} agents passed the schema lint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
