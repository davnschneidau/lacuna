"""
Diff scope calculator for LACUNA_MODE=diff.

Given a git diff (base_ref..head_ref), computes the set of files that should
be scanned:
  - directly changed files
  - files that import changed files (transitive, up to max_depth hops)
  - HTTP handler files that call into the changed set

The scope is serialised to JSON and injected into the child process env as
LACUNA_DIFF_SCOPE_JSON so the MCP recon server can filter its responses.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class DiffScope:
    """The computed set of files/endpoints in scope for a diff scan."""

    base_ref: str
    head_ref: str
    repo_name: str

    changed_files: list[str] = field(default_factory=list)
    transitive_files: list[str] = field(default_factory=list)
    affected_handler_files: list[str] = field(default_factory=list)

    @property
    def all_files(self) -> set[str]:
        return set(self.changed_files) | set(self.transitive_files) | set(self.affected_handler_files)

    def contains(self, filepath: str) -> bool:
        """Return True if the given repo-relative path is in scope."""
        clean = filepath.lstrip("/")
        return clean in self.all_files

    def is_empty(self) -> bool:
        return len(self.changed_files) == 0

    def to_env_dict(self) -> dict[str, str]:
        return {
            "LACUNA_DIFF_SCOPE_JSON": json.dumps({
                "repo": self.repo_name,
                "base_ref": self.base_ref,
                "head_ref": self.head_ref,
                "changed_files": self.changed_files,
                "transitive_files": self.transitive_files,
                "affected_handler_files": self.affected_handler_files,
            }),
        }

    def summary(self) -> str:
        total = len(self.all_files)
        return (
            f"Diff scope ({self.base_ref}..{self.head_ref}): "
            f"{len(self.changed_files)} changed files, "
            f"{len(self.transitive_files)} transitive imports, "
            f"{len(self.affected_handler_files)} affected handler files. "
            f"Total in scope: {total} files."
        )


def compute_diff_scope(
    repo_path: Path,
    base_ref: str,
    head_ref: str,
    repo_name: str,
    max_import_depth: int = 3,
) -> DiffScope:
    """Compute the diff scope for a single repo."""
    scope = DiffScope(base_ref=base_ref, head_ref=head_ref, repo_name=repo_name)

    changed = _git_diff_files(repo_path, base_ref, head_ref)
    scope.changed_files = sorted(changed)

    if not changed:
        return scope

    all_py_files = _find_python_files(repo_path)
    import_graph = _build_reverse_import_graph(repo_path, all_py_files)

    transitive: set[str] = set()
    frontier = set(changed)
    for _ in range(max_import_depth):
        next_frontier: set[str] = set()
        for f in frontier:
            for importer in import_graph.get(f, set()):
                if importer not in changed and importer not in transitive:
                    next_frontier.add(importer)
        if not next_frontier:
            break
        transitive |= next_frontier
        frontier = next_frontier

    scope.transitive_files = sorted(transitive)

    handler_patterns = [
        r"@app\.(get|post|put|patch|delete|route)",
        r"@router\.(get|post|put|patch|delete)",
        r"@blueprint\.(get|post|put|patch|delete|route)",
        r"urlpatterns\s*=",
        r"path\(['\"]",
        r"re_path\(['\"]",
    ]
    handler_re = re.compile("|".join(handler_patterns), re.IGNORECASE)

    all_in_scope = changed | transitive
    handlers: set[str] = set()
    for py_file in all_py_files:
        if py_file in all_in_scope:
            continue
        try:
            text = (repo_path / py_file).read_text(encoding="utf-8", errors="ignore")
            if handler_re.search(text):
                for in_scope_file in all_in_scope:
                    module_name = _path_to_module(in_scope_file)
                    if module_name and module_name in text:
                        handlers.add(py_file)
                        break
        except OSError:
            continue

    scope.affected_handler_files = sorted(handlers)
    return scope


def _git_diff_files(repo_path: Path, base_ref: str, head_ref: str) -> set[str]:
    """Return the set of repo-relative file paths changed between base and head."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            _warn(f"git diff failed: {result.stderr.strip()[:200]}")
            return set()
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        existing = {ln for ln in lines if (repo_path / ln).exists()}
        return existing
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        _warn(f"git diff error: {e}")
        return set()


def _find_python_files(repo_path: Path) -> list[str]:
    """Return repo-relative paths of all .py files, skipping vendored dirs."""
    _SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor"}
    results: list[str] = []
    for p in repo_path.rglob("*.py"):
        parts = set(p.relative_to(repo_path).parts)
        if parts & _SKIP:
            continue
        results.append(str(p.relative_to(repo_path)).replace("\\", "/"))
    return results


def _build_reverse_import_graph(
    repo_path: Path, py_files: Iterable[str]
) -> dict[str, set[str]]:
    """
    For each file, record which other files import it.
    Returns {imported_file: {set of files that import it}}.
    """
    graph: dict[str, set[str]] = {}

    for rel_path in py_files:
        abs_path = repo_path / rel_path
        try:
            source = abs_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=rel_path)
        except (OSError, SyntaxError):
            continue

        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.append(node.module)

        for mod in imported_modules:
            candidate = _module_to_path(mod)
            if candidate:
                graph.setdefault(candidate, set()).add(rel_path)

    return graph


def _module_to_path(module_name: str) -> str | None:
    """Convert a dotted module name to a repo-relative file path guess."""
    if not module_name or module_name.startswith(("os", "sys", "re", "json",
                                                   "typing", "collections",
                                                   "pathlib", "datetime")):
        return None
    parts = module_name.split(".")
    return "/".join(parts) + ".py"


def _path_to_module(rel_path: str) -> str | None:
    """Convert a repo-relative path to a dotted module name guess."""
    if not rel_path.endswith(".py"):
        return None
    return rel_path[:-3].replace("/", ".").replace("\\", ".")


def load_scope_from_env() -> DiffScope | None:
    """Load a DiffScope from LACUNA_DIFF_SCOPE_JSON env var. Returns None if not set."""
    import os
    raw = os.environ.get("LACUNA_DIFF_SCOPE_JSON")
    if not raw:
        return None
    try:
        data = json.loads(raw)
        scope = DiffScope(
            base_ref=data.get("base_ref", ""),
            head_ref=data.get("head_ref", ""),
            repo_name=data.get("repo", ""),
        )
        scope.changed_files = data.get("changed_files", [])
        scope.transitive_files = data.get("transitive_files", [])
        scope.affected_handler_files = data.get("affected_handler_files", [])
        return scope
    except (json.JSONDecodeError, KeyError):
        return None


def _warn(msg: str) -> None:
    sys.stderr.write(f"[diff-scope] {msg}\n")
    sys.stderr.flush()
