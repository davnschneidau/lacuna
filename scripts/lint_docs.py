#!/usr/bin/env python3
"""Documentation lint.

Validates that the documentation in this repository stays internally
consistent with the code. The lint covers:

1. **Glossary completeness.** Every defined term in
   ``docs/glossary.md`` has a single bolded heading. The lint does
   *not* try to assert "every concept the code uses is in the
   glossary" (impossible without semantic understanding); instead
   it catches duplicate definitions and malformed entries.

2. **Invariant cross-references.** Every ``INV-NNN`` mentioned
   anywhere under ``docs/`` resolves to a definition in
   ``docs/INVARIANTS.md``. Broken cross-references mean a reader
   chasing the citation hits a dead end.

3. **ADR numbering.** Every file under ``docs/adr/`` matches
   ``NNNN-*.md``; ids are unique; the template (``0001-template.md``)
   is exempt from "must implement a decision."

4. **Skill schema.** Every ``.claude/skills/<name>/SKILL.md`` file
   has the required frontmatter (``name``, ``description``,
   ``when_to_use``) per ``docs/skill-schema.md``.

5. **Code-block language tags.** Every fenced code block in every
   ``.md`` file under ``docs/`` and ``.claude/skills/`` has a
   language tag. Prevents the doc-as-test pass from skipping
   un-tagged blocks.

6. **Version consistency.** Delegated to ``scripts/lint_versions.py``
   — we just re-run it so a single ``python scripts/lint_docs.py``
   gives operators the whole picture.

Run from CI on every PR:

    python scripts/lint_docs.py

Exit codes:
    0 — every check passes
    1 — at least one violation
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
INVARIANTS_PATH = DOCS_DIR / "INVARIANTS.md"
GLOSSARY_PATH = DOCS_DIR / "glossary.md"

INV_REFERENCE = re.compile(r"\bINV-(\d{3})\b")
GLOSSARY_TERM = re.compile(r"^\*\*([^*]+)\*\*\s+\u2014")
CODE_FENCE = re.compile(r"^```([A-Za-z0-9_+\-]*)")
ADR_FILENAME = re.compile(r"(\d{4})-[a-z0-9][a-z0-9-]*\.md$")


def _iter_markdown(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.md") if p.is_file()]


def _glossary_terms() -> tuple[set[str], list[str]]:
    if not GLOSSARY_PATH.exists():
        return set(), [f"missing {GLOSSARY_PATH.relative_to(REPO_ROOT)}"]
    terms: list[str] = []
    for line in GLOSSARY_PATH.read_text(encoding="utf-8").splitlines():
        m = GLOSSARY_TERM.match(line)
        if m:
            terms.append(m.group(1).strip())
    seen: set[str] = set()
    dups: list[str] = []
    for t in terms:
        if t in seen:
            dups.append(t)
        seen.add(t)
    errors: list[str] = []
    for d in dups:
        errors.append(f"glossary defines {d!r} more than once")
    return seen, errors


def _invariant_ids() -> tuple[set[str], list[str]]:
    if not INVARIANTS_PATH.exists():
        return set(), [f"missing {INVARIANTS_PATH.relative_to(REPO_ROOT)}"]
    text = INVARIANTS_PATH.read_text(encoding="utf-8")
    defined: set[str] = set()
    for m in re.finditer(r"^## (INV-\d{3})\b", text, flags=re.MULTILINE):
        defined.add(m.group(1))
    return defined, []


def _check_invariant_references(defined: set[str]) -> list[str]:
    errors: list[str] = []
    for path in _iter_markdown(DOCS_DIR):
        if path == INVARIANTS_PATH:
            continue
        text = path.read_text(encoding="utf-8")
        for m in INV_REFERENCE.finditer(text):
            ref = f"INV-{m.group(1)}"
            if ref not in defined:
                lineno = text[:m.start()].count("\n") + 1
                errors.append(
                    f"{path.relative_to(REPO_ROOT)}:{lineno} references "
                    f"{ref} but it is not defined in INVARIANTS.md",
                )
    return errors


def _check_adr() -> list[str]:
    adr_dir = DOCS_DIR / "adr"
    if not adr_dir.exists():
        return [f"missing {adr_dir.relative_to(REPO_ROOT)}"]
    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    for p in sorted(adr_dir.glob("*.md")):
        m = ADR_FILENAME.search(p.name)
        if not m:
            errors.append(
                f"{p.relative_to(REPO_ROOT)} does not match NNNN-slug.md",
            )
            continue
        adr_id = m.group(1)
        if adr_id in seen_ids:
            errors.append(
                f"ADR id {adr_id} used by both {seen_ids[adr_id]} and "
                f"{p.name}",
            )
        seen_ids[adr_id] = p.name
    if "0001" not in seen_ids:
        errors.append("missing docs/adr/0001-template.md")
    return errors


def _check_skill_frontmatter() -> list[str]:
    if not SKILLS_DIR.exists():
        return []
    errors: list[str] = []
    for skill_dir in sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir()):
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            errors.append(
                f"{skill_dir.relative_to(REPO_ROOT)} has no SKILL.md",
            )
            continue
        text = skill_md.read_text(encoding="utf-8")
        if not text.startswith("---"):
            errors.append(
                f"{skill_md.relative_to(REPO_ROOT)} missing frontmatter",
            )
            continue
        end = text.find("\n---", 4)
        if end == -1:
            errors.append(
                f"{skill_md.relative_to(REPO_ROOT)} unterminated frontmatter",
            )
            continue
        front = text[4:end]
        for required in ("name:", "description:", "when_to_use:"):
            if required not in front:
                errors.append(
                    f"{skill_md.relative_to(REPO_ROOT)} missing "
                    f"frontmatter key {required.rstrip(':')!r}",
                )
    return errors


def _check_code_fence_languages() -> list[str]:
    errors: list[str] = []
    for root in (DOCS_DIR, SKILLS_DIR):
        if not root.exists():
            continue
        for path in _iter_markdown(root):
            in_fence = False
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1,
            ):
                m = CODE_FENCE.match(line)
                if not m:
                    continue
                if in_fence:
                    in_fence = False
                    continue
                in_fence = True
                lang = m.group(1).strip()
                if not lang:
                    errors.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno} fenced "
                        f"code block has no language tag",
                    )
    return errors


def _run_version_lint() -> list[str]:
    script = REPO_ROOT / "scripts" / "lint_versions.py"
    if not script.exists():
        return [f"missing {script.relative_to(REPO_ROOT)}"]
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True,
    )
    if proc.returncode == 0:
        return []
    return [
        "scripts/lint_versions.py failed (see its output for detail):",
        proc.stdout.strip() or proc.stderr.strip(),
    ]


def main() -> int:
    all_errors: list[str] = []
    _, gerr = _glossary_terms()
    all_errors.extend(gerr)
    defined_invariants, ierr = _invariant_ids()
    all_errors.extend(ierr)
    all_errors.extend(_check_invariant_references(defined_invariants))
    all_errors.extend(_check_adr())
    all_errors.extend(_check_skill_frontmatter())
    all_errors.extend(_check_code_fence_languages())
    all_errors.extend(_run_version_lint())

    if all_errors:
        print("FAIL: lint_docs.py found problems:", file=sys.stderr)
        for e in all_errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("OK: docs lint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
