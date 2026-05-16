"""Repo policy regression tests.

Cover the documentation-, version-, and topology-side invariants so
that future PRs cannot silently regress them:

* ``scripts/lint_agents.py`` must pass against the current
  ``.claude/agents/`` corpus.
* ``scripts/lint_docs.py`` must pass against the current
  ``docs/`` and ``.claude/skills/`` corpora.
* ``scripts/lint_versions.py`` must pass on the live repo and the
  handful of artifacts that name a version literal must agree with
  ``lacuna.__version__``.
* ``scripts/lint_topology.py`` must pass (every agent classified).
* Every ``INV-NNN`` referenced in repo markdown resolves to a
  definition in ``docs/INVARIANTS.md``.
* Every glossary term is defined exactly once.
* ``docs/adr/0001-template.md`` exists and the ADR ids are unique.
* Each currently shipped skill exposes the required ``when_to_use``
  frontmatter key (the discoverability contract from
  ``docs/skill-schema.md``).

These tests intentionally invoke the scripts as subprocesses rather
than importing them -- the scripts are the lint contract, and we
want the same code path the CI lint job will use.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
DOCS_DIR = REPO_ROOT / "docs"
INVARIANTS_PATH = DOCS_DIR / "INVARIANTS.md"
GLOSSARY_PATH = DOCS_DIR / "glossary.md"
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"

INV_REFERENCE = re.compile(r"\bINV-(\d{3})\b")


def _run_script(name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


# ─── Lint scripts ───────────────────────────────────────────────────────────

def test_lint_agents_script_passes() -> None:
    result = _run_script("lint_agents.py")
    assert result.returncode == 0, (
        f"lint_agents.py failed:\n{result.stdout}\n{result.stderr}"
    )


def test_lint_docs_script_passes() -> None:
    result = _run_script("lint_docs.py")
    assert result.returncode == 0, (
        f"lint_docs.py failed:\n{result.stdout}\n{result.stderr}"
    )


def test_lint_versions_script_passes() -> None:
    result = _run_script("lint_versions.py")
    assert result.returncode == 0, (
        f"lint_versions.py failed:\n{result.stdout}\n{result.stderr}"
    )


def test_topology_lint_includes_adversary_agents() -> None:
    result = _run_script("lint_topology.py")
    assert result.returncode == 0, result.stderr


# ─── Version consistency ────────────────────────────────────────────────────

def test_readme_headline_matches_canonical_version() -> None:
    from lacuna import __version__
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"**{__version__}**" in readme, (
        f"README.md headline does not mention canonical version {__version__}"
    )


def test_changelog_top_entry_matches_canonical_version() -> None:
    from lacuna import __version__
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = [
        line for line in changelog.splitlines()
        if line.startswith("## ")
    ]
    assert headings, "CHANGELOG.md has no ## entries"
    assert headings[0].split()[1] == __version__, (
        f"CHANGELOG.md top heading is {headings[0]!r}, "
        f"expected ## {__version__} ..."
    )


def test_pipe_yml_image_tag_matches_canonical_version() -> None:
    from lacuna import __version__
    pipe_yml = (
        REPO_ROOT / "bitbucket-pipe" / "pipe.yml"
    ).read_text(encoding="utf-8")
    assert f"image: lacuna:{__version__}" in pipe_yml, (
        f"bitbucket-pipe/pipe.yml does not pin the canonical {__version__}"
    )


def test_pyproject_uses_dynamic_version() -> None:
    """The pyproject MUST NOT pin a literal -- it must read __init__.py."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dynamic = [" in pyproject and '"version"' in pyproject
    assert 'version = "3' not in pyproject, (
        "pyproject.toml hard-codes a version literal; it must use "
        "dynamic = ['version'] and read from src/lacuna/__init__.py"
    )


# ─── Invariants & glossary ──────────────────────────────────────────────────

def test_invariants_doc_defines_at_least_eight_ids() -> None:
    assert INVARIANTS_PATH.exists()
    text = INVARIANTS_PATH.read_text(encoding="utf-8")
    ids = {m.group(0) for m in re.finditer(r"INV-\d{3}", text)}
    assert len(ids) >= 8, (
        f"INVARIANTS.md should define at least 8 invariants; "
        f"found {len(ids)}: {sorted(ids)}",
    )


def test_every_invariant_reference_resolves() -> None:
    text = INVARIANTS_PATH.read_text(encoding="utf-8")
    defined = {
        m.group(0)
        for m in re.finditer(r"^## (INV-\d{3})", text, flags=re.MULTILINE)
    }
    broken: list[str] = []
    for path in DOCS_DIR.rglob("*.md"):
        if path == INVARIANTS_PATH:
            continue
        body = path.read_text(encoding="utf-8")
        for m in INV_REFERENCE.finditer(body):
            ref = f"INV-{m.group(1)}"
            if ref not in defined:
                broken.append(f"{path.name} cites {ref} (undefined)")
    assert not broken, "\n".join(broken)


def test_glossary_terms_are_unique() -> None:
    assert GLOSSARY_PATH.exists()
    text = GLOSSARY_PATH.read_text(encoding="utf-8")
    terms: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\*\*([^*]+)\*\*\s+\u2014", line)
        if match:
            terms.append(match.group(1).strip())
    seen: set[str] = set()
    dups: list[str] = []
    for term in terms:
        if term in seen:
            dups.append(term)
        seen.add(term)
    assert not dups, f"glossary duplicates: {dups}"
    assert len(terms) >= 10, (
        f"glossary should have at least 10 entries; found {len(terms)}"
    )


# ─── ADRs & skill schema ────────────────────────────────────────────────────

def test_adr_template_exists_and_ids_are_unique() -> None:
    adr_dir = DOCS_DIR / "adr"
    assert adr_dir.exists()
    template = adr_dir / "0001-template.md"
    assert template.exists(), "missing 0001-template.md"
    seen: dict[str, str] = {}
    for path in adr_dir.glob("*.md"):
        m = re.match(r"(\d{4})-", path.name)
        if not m:
            continue
        adr_id = m.group(1)
        assert adr_id not in seen, (
            f"ADR id {adr_id} reused: {seen[adr_id]} and {path.name}"
        )
        seen[adr_id] = path.name


@pytest.mark.parametrize(
    "skill_dir",
    sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir()),
    ids=lambda p: p.name,
)
def test_every_skill_has_when_to_use(skill_dir: Path) -> None:
    skill_md = skill_dir / "SKILL.md"
    assert skill_md.exists(), f"{skill_dir.name} missing SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    assert text.startswith("---"), (
        f"{skill_dir.name}/SKILL.md missing frontmatter"
    )
    end = text.find("\n---", 4)
    assert end != -1, (
        f"{skill_dir.name}/SKILL.md has unterminated frontmatter"
    )
    front = text[4:end]
    assert "when_to_use:" in front, (
        f"{skill_dir.name}/SKILL.md missing 'when_to_use:' "
        f"per docs/skill-schema.md",
    )


def test_skill_schema_doc_exists() -> None:
    schema = DOCS_DIR / "skill-schema.md"
    assert schema.exists(), "docs/skill-schema.md must exist"
    body = schema.read_text(encoding="utf-8")
    for required_token in (
        "name:",
        "description:",
        "when_to_use:",
        "## Required frontmatter",
        "## Required sections",
        "## Anti-patterns",
    ):
        assert required_token in body, (
            f"skill-schema.md missing reference to {required_token!r}"
        )
