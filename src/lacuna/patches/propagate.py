"""
Variant propagator.

Takes a generated rule (from patch_essence) and runs it against the
codebase. Returns all matching sites — these are candidates for the
"same bug pattern, different location" lookalike search.

We wrap semgrep when available (the standard tool), but fall back to a
pure-Python regex-based matcher that handles the simplest rule shape so
the v3 codebase still works in environments without semgrep installed.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class PropagationMatch:
    file: str
    line: int
    matched_text: str
    rule_id: str


def propagate_pattern(
    repo_root: Path, rule_yaml: str,
    max_matches: int = 100,
    timeout_seconds: int = 120,
) -> dict:
    """Run a rule against the repo. Returns {summary, matches}."""
    # Try semgrep first
    matches = _run_semgrep(rule_yaml, repo_root, timeout_seconds)
    if matches is None:
        # Fallback: regex-based matcher
        matches = _run_regex_fallback(rule_yaml, repo_root)

    matches = matches[:max_matches]

    return {
        "summary": f"propagate: {len(matches)} matches in {repo_root.name}",
        "matches": [
            {
                "file": m.file, "line": m.line,
                "matched_text": m.matched_text[:200],
                "rule_id": m.rule_id,
            } for m in matches
        ],
    }


def _run_semgrep(
    rule_yaml: str, repo_root: Path, timeout_seconds: int,
) -> list[PropagationMatch] | None:
    """Run semgrep with the rule. Returns None if semgrep unavailable."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False,
        ) as f:
            f.write(rule_yaml)
            rule_path = f.name
        cmd = [
            "semgrep", "--config", rule_path,
            "--json", "--no-git-ignore",
            "--timeout", str(timeout_seconds // 2),
            str(repo_root),
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None
    finally:
        try:
            import os
            os.unlink(rule_path)
        except (OSError, NameError):
            pass

    if proc.returncode not in (0, 1):  # 0 = no findings, 1 = findings
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None

    out: list[PropagationMatch] = []
    for r in data.get("results", []):
        out.append(PropagationMatch(
            file=r.get("path", "?"),
            line=r.get("start", {}).get("line", 0),
            matched_text=r.get("extra", {}).get("lines", "")[:300],
            rule_id=r.get("check_id", "patch-essence"),
        ))
    return out


_FALLBACK_SUFFIXES = frozenset({
    ".py", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".java", ".go", ".js", ".ts", ".rb", ".cs",
})
_FALLBACK_SKIP_RE = re.compile(
    r"[\\/](\.git|node_modules|\.venv|venv|__pycache__|dist|build|"
    r"target|vendor)[\\/]"
)


def _run_regex_fallback(
    rule_yaml: str, repo_root: Path,
) -> list[PropagationMatch]:
    """Best-effort regex match from the rule's pattern field.

    Semgrep rules use AST-aware matching; we approximate with regex.
    This catches the most obvious cases when semgrep isn't installed,
    at the cost of false positives.
    """
    try:
        rule_doc = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        return []
    if not rule_doc or "rules" not in rule_doc:
        return []

    matches: list[PropagationMatch] = []
    file_cache: dict[Path, str] = {}

    def _read(path: Path) -> str | None:
        if path in file_cache:
            return file_cache[path]
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return None
        file_cache[path] = text
        return text

    candidate_files: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if _FALLBACK_SKIP_RE.search(str(p)):
            continue
        if p.suffix not in _FALLBACK_SUFFIXES:
            continue
        candidate_files.append(p)

    for rule in rule_doc["rules"]:
        rule_id = rule.get("id", "unknown")
        pattern = rule.get("pattern", "")
        if not pattern or pattern == "...":
            continue
        regex_src = _pattern_to_regex(pattern)
        try:
            # DOTALL so ``...`` (translated to ``.*?``) crosses newlines,
            # MULTILINE so anchors line up with diff-style snippets.
            regex = re.compile(regex_src, re.DOTALL | re.MULTILINE)
        except re.error:
            continue

        for p in candidate_files:
            text = _read(p)
            if text is None:
                continue
            for m in regex.finditer(text):
                line_no = text[: m.start()].count("\n") + 1
                snippet = text[m.start():m.start() + 200]
                matches.append(PropagationMatch(
                    file=str(p.relative_to(repo_root)),
                    line=line_no,
                    matched_text=snippet,
                    rule_id=rule_id,
                ))
                if len(matches) >= 200:
                    return matches
    return matches


def _pattern_to_regex(pattern: str) -> str:
    r"""Crude semgrep pattern → regex translator.

    Handles:
      $METAVAR    → \w+ (any case — semgrep itself allows ``$x``)
      $...METAVAR → .*? (ellipsis metavars match a span)
      ...         → .*?
      literal text → escaped
      whitespace runs collapse to ``\s+`` so indentation differences
      between the patch and the haystack don't defeat the match.
    """
    parts: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "$" and i + 1 < n:
            j = i + 1
            # Optional ellipsis-metavar prefix: ``$...FOO`` and ``$..FOO``.
            if pattern[j:j+3] == "...":
                j += 3
                while j < n and (pattern[j].isalnum() or pattern[j] == "_"):
                    j += 1
                parts.append(r".*?")
                i = j
                continue
            if (pattern[j].isalpha() or pattern[j] == "_"):
                while j < n and (pattern[j].isalnum() or pattern[j] == "_"):
                    j += 1
                parts.append(r"\w+")
                i = j
                continue
        if pattern[i:i+3] == "...":
            parts.append(r".*?")
            i += 3
            continue
        if ch.isspace():
            j = i + 1
            while j < n and pattern[j].isspace():
                j += 1
            parts.append(r"\s+")
            i = j
            continue
        parts.append(re.escape(ch))
        i += 1
    return "".join(parts)
