#!/usr/bin/env python3
"""
Enforce single-source-of-truth for the Lacuna version string.

The canonical value lives at ``src/lacuna/__init__.py:__version__``. This
script walks the tracked files in the repo, looks for any file that
hard-codes a literal version that *disagrees* with the canonical value,
and fails with a non-zero exit code if it finds one.

Files that are deliberately allowed to mention historical versions
(``CHANGELOG.md``) are exempted via ``ALLOWLIST``. The canonical file
itself is also exempted (it *defines* the version).

Run from CI on every PR:

    python scripts/lint_versions.py

Exit codes:
    0  — every file is either silent on version or quotes the canonical one.
    1  — at least one file pins a literal version that doesn't match.
    2  — script couldn't read the canonical value at all.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_FILE = REPO_ROOT / "src" / "lacuna" / "__init__.py"

# Files we won't lint. CHANGELOG.md mentions historical versions on
# purpose; pyproject.toml uses dynamic = ["version"]; tests/fixtures may
# include unrelated version-shaped strings (e.g. OpenAPI ``3.0.0``).
ALLOWLIST: set[Path] = {
    CANONICAL_FILE,
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "pyproject.toml",
}

# Glob-style suffix exclusions (no version strings expected, but we don't
# want false positives from build / cache artifacts).
EXCLUDE_DIRS = {
    ".git", "__pycache__", "node_modules", ".pytest_cache",
    ".venv", "venv", "build", "dist", "htmlcov",
}

# Match SemVer-shaped strings that are *plausibly* a Lacuna version.
#
# We deliberately restrict to *Lacuna-shaped* contexts to avoid false
# positives from third-party version literals embedded in fixtures and
# gadget catalogs (e.g. OpenAPI ``"openapi": "3.0.0"`` or .NET
# ``System, Version=4.0.0.0``). The patterns are anchored to:
#
# - ``lacuna:<ver>`` / ``lacuna/<ver>`` / ``lacuna-<ver>`` image tags
# - ``acme/lacuna:<ver>`` and ``<reg>/lacuna:<ver>`` Docker URIs
# - ``docker://.../lacuna:<ver>`` pipeline declarations
# - ``__version__ = "<ver>"`` canonical assignments (other Python files)
# - ``"Lacuna <ver>"`` strings (CLI banners, headers)
LACUNA_CONTEXT = re.compile(
    r"""(?x)
    (?:
        /lacuna:                               # ``…/lacuna:3.1.1``
      | (?<![A-Za-z])lacuna[:/-]               # word-boundary ``lacuna:``…
      | docker://[^"'`\s]{0,120}lacuna[:/-]    # ``docker://acme/lacuna:…``
      | __version__\s*=\s*"                    # canonical assignment
      | (?<![A-Za-z])Lacuna\s+                 # ``Lacuna 3.1.1`` banner
    )
    "?(\d+\.\d+\.\d+)
    """,
)


def canonical_version() -> str:
    text = CANONICAL_FILE.read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not m:
        print(
            f"ERROR: could not parse __version__ from {CANONICAL_FILE}",
            file=sys.stderr,
        )
        sys.exit(2)
    return m.group(1)


def walk_files() -> list[Path]:
    out: list[Path] = []
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.suffix in {".pyc", ".png", ".jpg", ".jpeg", ".pdf", ".woff",
                        ".woff2", ".sqlite", ".db"}:
            continue
        if p in ALLOWLIST:
            continue
        out.append(p)
    return out


def find_drift(canonical: str) -> list[tuple[Path, int, str, str]]:
    drift: list[tuple[Path, int, str, str]] = []
    for path in walk_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in LACUNA_CONTEXT.finditer(line):
                literal = m.group(1)
                if literal != canonical:
                    drift.append((path, lineno, line.rstrip(), literal))
    return drift


def main() -> int:
    canonical = canonical_version()
    drift = find_drift(canonical)
    if not drift:
        print(f"OK: all version mentions match canonical {canonical}.")
        return 0
    print(
        f"FAIL: canonical version is {canonical} "
        f"({CANONICAL_FILE.relative_to(REPO_ROOT)}), "
        f"but {len(drift)} drifted mention(s) found:",
        file=sys.stderr,
    )
    for path, lineno, line, literal in drift:
        rel = path.relative_to(REPO_ROOT)
        print(
            f"  {rel}:{lineno}  pinned={literal!r}  expected={canonical!r}",
            file=sys.stderr,
        )
        print(f"    {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
