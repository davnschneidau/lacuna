"""
Patch essence extractor.

Given a git commit (or raw diff text), extract:
  - Files changed
  - Per-hunk diff
  - AST-level diff: what got added (checks/sanitizers/type guards),
    what got removed (dangerous calls/unsafe blocks)
  - A semgrep-style rule that matches the BEFORE pattern, so variants
    can be found elsewhere.
  - A 1-paragraph "essence" describing the bug class

This is the heart of variant-hunting. It works without external CVE
corpus access — operates on the user's own git history.

Approach (heuristic but real):
  1. `git show <sha>` → unified diff
  2. Parse hunks; for each hunk, classify added/removed lines
  3. Identify "guard introductions": added lines matching common safety
     patterns (if-checks, instanceof, isinstance, bounds checks, escape
     calls, sanitize calls, null-checks, length checks).
  4. Identify "dangerous removals": removed lines matching known sink
     patterns (raw concat into queries, eval/exec, deserialize without
     guard, unsafe casts, format-string sinks).
  5. The BEFORE pattern is what existed before the guard was added.
     Generate a semgrep rule from that BEFORE shape.
  6. Classify the bug class (CWE) by examining the guard kind.

Output: PatchRule dataclass with rule_yaml, before_pattern, after_pattern,
essence_md, bug_class.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


# Patterns that indicate a *guard was added* in the after-state.
GUARD_PATTERNS = {
    "CWE-20":  [
        re.compile(r"\bisinstance\s*\("),
        re.compile(r"\binstanceof\s+[A-Z]\w+"),
        re.compile(r"\btype\s*\(\s*\w+\s*\)\s*[=!]="),
    ],
    "CWE-89":  [  # SQL injection
        re.compile(r"\bparameterize|\bprepare(d)?Statement|"
                    r"\bbind(_param|Value)|\bexecute\s*\(\s*\w+\s*,\s*\("),
        re.compile(r"\bquote_ident\b|\bescape_sql\b"),
    ],
    "CWE-79":  [  # XSS
        re.compile(r"\bescape\s*\(|\bhtml\.escape\b|\bhtmlspecialchars\b|"
                    r"\bsanitize\s*\("),
        re.compile(r"\|\s*e\b|\|\s*escape\b"),  # template filter
    ],
    "CWE-22":  [  # path traversal
        re.compile(r"\.\.\\?|\brealpath\s*\(|\babspath\s*\(|"
                    r"\bnormalize\s*\("),
        re.compile(r"\bos\.path\.join\b|\bpathlib\.Path"),
    ],
    "CWE-78":  [  # OS command injection
        re.compile(r"\bshlex\.quote\b|\bshell=False\b|"
                    r"\bsubprocess\.run\s*\(\s*\["),
    ],
    "CWE-190": [  # integer overflow
        re.compile(r"\bif\s*\([^)]*[<>][^)]*MAX|>\s*INT_MAX"),
        re.compile(r"\b__builtin_mul_overflow\b|"
                    r"\bckd_mul\b|\bckd_add\b"),
    ],
    "CWE-416": [  # use-after-free
        re.compile(r"\bp\s*=\s*NULL\b|\b=\s*nullptr\b"),
    ],
    "CWE-918": [  # SSRF
        re.compile(r"\ballowlist|\bwhitelist|\bvalidate_url"),
    ],
    "CWE-352": [  # CSRF
        re.compile(r"\bcsrf_token|\bvalidate_csrf"),
    ],
    "CWE-502": [  # unsafe deserialize
        re.compile(r"\bsafe_load\b|\bAllowList\b|\bsetSafeMode\b"),
    ],
    "CWE-200": [  # information exposure
        re.compile(r"\bredact|\bmask_pii|\bsanitize_log"),
    ],
    "CWE-287": [  # auth
        re.compile(r"\bcurrent_user\b.*\bauth|\bcheck_permission|"
                    r"\b@login_required|\brequire_auth"),
    ],
    "CWE-863": [  # authz
        re.compile(r"\bcan\s*\(|\bauthorize\s*\(|\b@requires_role"),
    ],
    "CWE-134": [  # format string
        re.compile(r'printf\s*\(\s*"%s"\s*,'),
    ],
    "CWE-117": [  # log injection / log4shell
        re.compile(r"\bformatMsgNoLookups|StringSubstitutor.disable|"
                    r"\.replaceAll\s*\(\s*['\"][$%]"),
    ],
    "CWE-94":  [  # code injection
        re.compile(r"\bast\.literal_eval\b|\bjson\.loads\b"),
    ],
}

# Sink patterns — *removed* lines that match these are evidence of a
# dangerous call being eliminated.
SINK_PATTERNS = {
    "CWE-89":  [re.compile(r'"\s*\+\s*\w+|f"[^"]*\{[^}]+\}.*WHERE|'
                            r'\.query\s*\(\s*["\'][^"\']*["\']\s*\+'),
                re.compile(r'execute\s*\(\s*[^,)]*%s')],
    "CWE-78":  [re.compile(r"\bos\.system|\bsubprocess.*shell=True|"
                            r"\beval\s*\(|\bexec\s*\("),
                re.compile(r"\bRuntime.getRuntime\(\)\.exec")],
    "CWE-79":  [re.compile(r"\binnerHTML\s*=|\bdocument\.write|"
                            r"\|\s*safe\b|\{\{\{")],
    "CWE-502": [re.compile(r"\bpickle\.loads|\byaml\.load\s*\(|"
                            r"\bunserialize|\bObjectInputStream.*readObject"),
                re.compile(r"\.readObject\s*\(")],
    "CWE-22":  [re.compile(r"\bopen\s*\(\s*[\w.]+\s*\+|"
                            r"\bos\.path\.join.*request")],
    "CWE-918": [re.compile(r"\brequests\.(get|post)\s*\(\s*\w+\)|"
                            r"\burllib.request.urlopen\s*\(\s*\w+\)")],
    "CWE-190": [re.compile(r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\)")],
    "CWE-134": [re.compile(r"\bprintf\s*\(\s*\w+\s*\)|"
                            r"\bsprintf\s*\(\s*\w+\s*,\s*\w+\s*\)")],
}


@dataclass
class PatchHunk:
    file: str
    old_start: int
    new_start: int
    removed_lines: list[str] = field(default_factory=list)
    added_lines: list[str] = field(default_factory=list)


@dataclass
class PatchEssence:
    source_ref: str                 # commit sha or "diff"
    files_changed: list[str]
    hunks: list[PatchHunk]
    bug_class: str | None           # CWE
    before_pattern: str | None      # the dangerous snippet
    after_pattern: str | None       # the safe snippet
    essence_md: str
    rule_yaml: str
    confidence: float


def extract_essence(
    commit_sha: str | None = None,
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> PatchEssence | None:
    """Extract the essence from a commit or a raw diff.

    Provide either commit_sha (and repo_root) OR diff_text.
    """
    if diff_text is None and commit_sha:
        if not repo_root:
            return None
        try:
            proc = subprocess.run(
                ["git", "show", "--unified=3", commit_sha],
                cwd=str(repo_root),
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return None
            diff_text = proc.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    if not diff_text:
        return None

    hunks = _parse_unified_diff(diff_text)
    if not hunks:
        return None

    files_changed = sorted({h.file for h in hunks})
    bug_class, before_snippet, after_snippet, conf = _classify(hunks)

    rule_yaml = generate_rule(
        before_snippet, bug_class or "CWE-other",
        commit_sha or "diff",
    )

    essence_md = _build_essence_md(
        commit_sha or "diff", bug_class, before_snippet,
        after_snippet, files_changed,
    )

    return PatchEssence(
        source_ref=commit_sha or "diff",
        files_changed=files_changed,
        hunks=hunks,
        bug_class=bug_class,
        before_pattern=before_snippet,
        after_pattern=after_snippet,
        essence_md=essence_md,
        rule_yaml=rule_yaml,
        confidence=conf,
    )


# ─── Diff parsing ───────────────────────────────────────────────────────────

HUNK_HEADER_RE = re.compile(
    r"^@@\s*-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s*@@",
)
DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)")


def _parse_unified_diff(text: str) -> list[PatchHunk]:
    hunks: list[PatchHunk] = []
    current_file: str | None = None
    current_hunk: PatchHunk | None = None
    for raw in text.splitlines():
        if m := DIFF_FILE_RE.match(raw):
            current_file = m.group(2)
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if m := HUNK_HEADER_RE.match(raw):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = PatchHunk(
                file=current_file or "<unknown>",
                old_start=int(m.group(1)),
                new_start=int(m.group(2)),
            )
            continue
        if current_hunk is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            current_hunk.added_lines.append(raw[1:])
        elif raw.startswith("-") and not raw.startswith("---"):
            current_hunk.removed_lines.append(raw[1:])
    if current_hunk:
        hunks.append(current_hunk)
    # Filter: drop hunks with no actual +/- lines
    return [h for h in hunks if (h.added_lines or h.removed_lines)]


# ─── Classification ─────────────────────────────────────────────────────────


def _classify(
    hunks: list[PatchHunk],
) -> tuple[str | None, str | None, str | None, float]:
    """Determine bug class and before/after snippets.

    Returns (cwe, before_snippet, after_snippet, confidence).
    """
    # Tally evidence per CWE
    guard_evidence: dict[str, int] = {}
    sink_evidence: dict[str, int] = {}

    for h in hunks:
        for line in h.added_lines:
            for cwe, patterns in GUARD_PATTERNS.items():
                for p in patterns:
                    if p.search(line):
                        guard_evidence[cwe] = guard_evidence.get(cwe, 0) + 1
                        break
        for line in h.removed_lines:
            for cwe, patterns in SINK_PATTERNS.items():
                for p in patterns:
                    if p.search(line):
                        sink_evidence[cwe] = sink_evidence.get(cwe, 0) + 1
                        break

    # Combine: prefer CWE with BOTH a guard add and a sink remove
    bug_class = None
    conf = 0.0
    for cwe in set(guard_evidence) & set(sink_evidence):
        score = guard_evidence[cwe] + sink_evidence[cwe] + 2
        if score > conf:
            bug_class = cwe
            conf = min(0.85, 0.5 + score * 0.1)

    # If only one side has evidence, use it at lower confidence
    if bug_class is None and guard_evidence:
        bug_class = max(guard_evidence, key=lambda k: guard_evidence[k])
        conf = min(0.65, 0.4 + guard_evidence[bug_class] * 0.05)
    elif bug_class is None and sink_evidence:
        bug_class = max(sink_evidence, key=lambda k: sink_evidence[k])
        conf = min(0.65, 0.4 + sink_evidence[bug_class] * 0.05)
    elif bug_class is None:
        bug_class = None
        conf = 0.3

    # Build before/after snippets from the most relevant hunk
    primary_hunk = max(
        hunks,
        key=lambda h: len(h.removed_lines) + len(h.added_lines),
    )
    before = "\n".join(primary_hunk.removed_lines[:8]) or None
    after = "\n".join(primary_hunk.added_lines[:8]) or None

    return bug_class, before, after, conf


# ─── Rule generation ────────────────────────────────────────────────────────


def generate_rule(
    before_snippet: str | None, bug_class: str, source_ref: str,
) -> str:
    """Generate a semgrep-compatible rule from a before-state snippet.

    We use a simple meta-variable substitution scheme: identifiers in the
    snippet become `$X1`, `$X2` etc. Literals and operators are preserved.
    This produces a syntactically loose pattern that catches the bug
    *shape* without over-fitting to specific variable names.
    """
    if not before_snippet:
        return f"# no before-snippet available for {source_ref}\nrules: []"

    pattern = _pattern_from_snippet(before_snippet)
    languages = _guess_languages(before_snippet)
    rule = f"""rules:
  - id: patch-essence-{_safe_id(source_ref)}
    message: |
      Pattern matches the BEFORE-state of a security-relevant fix in
      {source_ref}. Bug class: {bug_class}.
    languages: {languages}
    severity: WARNING
    pattern: |
      {pattern}
    metadata:
      cwe: "{bug_class}"
      source_ref: "{source_ref}"
      auto_generated: true
"""
    return rule


def _pattern_from_snippet(snippet: str) -> str:
    """Convert a code snippet into a semgrep-style pattern with metavars."""
    # Strip whitespace-only lines
    lines = [l for l in snippet.splitlines() if l.strip()]
    if not lines:
        return "..."

    pattern_lines: list[str] = []
    for line in lines[:5]:
        # Replace identifiers (lowercase words ≥2 chars) with semgrep metavars
        # but preserve language keywords and operators
        KEYWORDS = {
            "if", "else", "while", "for", "return", "def", "class", "func",
            "function", "var", "let", "const", "new", "in", "is", "not", "and",
            "or", "true", "false", "null", "None", "true", "False",
            "void", "int", "char", "size_t", "static", "extern", "public",
            "private", "protected", "self", "this",
        }
        var_idx = [0]
        seen: dict[str, str] = {}
        def replace_id(m):
            ident = m.group(0)
            if ident.lower() in KEYWORDS or ident.isdigit():
                return ident
            if ident in seen:
                return seen[ident]
            var_idx[0] += 1
            mv = f"$X{var_idx[0]}"
            seen[ident] = mv
            return mv
        pattern = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", replace_id, line)
        pattern_lines.append(pattern.strip())

    # Join with ellipsis if multi-line
    if len(pattern_lines) == 1:
        return pattern_lines[0]
    return "\n      ".join(pattern_lines)


def _guess_languages(snippet: str) -> str:
    """Guess languages based on syntactic hints."""
    hints = {
        "python": [r"\bdef\s+\w+\(", r"\bself\b", r"\.format\("],
        "javascript": [r"\bfunction\b", r"\bconst\b\s+\w+", r"=>\s*\{"],
        "go": [r"\bfunc\s+\w+\(", r":="],
        "java": [r"\bpublic\s+(class|void|static)", r"\bnew\s+[A-Z]\w+\("],
        "c": [r"\bmalloc\b", r"\bfree\b", r"\bvoid\b\s+\*"],
    }
    langs = []
    for lang, patterns in hints.items():
        if any(re.search(p, snippet) for p in patterns):
            langs.append(lang)
    return "[" + ", ".join(langs) + "]" if langs else "[generic]"


def _safe_id(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", s)[:40]


def _build_essence_md(
    source_ref: str, bug_class: str | None,
    before: str | None, after: str | None,
    files: list[str],
) -> str:
    parts = [
        f"## Patch Essence: {source_ref}",
        f"**Bug class:** {bug_class or 'unclassified'}",
        f"**Files changed:** {', '.join(files[:5])}"
        + (f" (+{len(files)-5} more)" if len(files) > 5 else ""),
    ]
    if before:
        parts.append("**Before (vulnerable):**\n```\n" + before + "\n```")
    if after:
        parts.append("**After (fixed):**\n```\n" + after + "\n```")
    parts.append(
        "**Variant search:** this rule may match other instances of the "
        "same pattern elsewhere in the codebase. Run `propagate_pattern` "
        "with the generated rule_yaml to find variants."
    )
    return "\n\n".join(parts)


def to_dict(p: PatchEssence) -> dict:
    return {
        "source_ref": p.source_ref,
        "files_changed": p.files_changed,
        "bug_class": p.bug_class,
        "before_pattern": p.before_pattern,
        "after_pattern": p.after_pattern,
        "essence_md": p.essence_md,
        "rule_yaml": p.rule_yaml,
        "confidence": p.confidence,
        "hunks_count": len(p.hunks),
    }
