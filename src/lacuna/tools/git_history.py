"""
Git history analysis helpers.

These tools read commit metadata, blame data, and file deletion history from
the repository's `.git` directory via `git` shell commands. The output is
shaped for the "summary + facets + handles" pattern used by all recon tools.

Why this matters: Mythos-style depth often comes from comparing the same
code at two points in time. "Why was this check added?" "What was deleted
recently?" "Which commits mention CVEs or security fixes?" Bugs cluster
where someone fixed something nearby badly — git history is the map.
"""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path


SECURITY_RELEVANT_KEYWORDS = re.compile(
    r"\b(CVE-\d{4}-\d+|security|vuln(?:erability)?|exploit|sanitiz|inject(?:ion)?|"
    r"escape|XSS|SSRF|RCE|IDOR|auth(?:n|z)?\sfix|csrf|sql(?:i| injection)?|"
    r"prototype pollution|deserializ|hardcod(?:ed)?\skey|secret\sleak|"
    r"timing attack|side[\s-]?channel|patch|fix.*(?:bypass|leak|expos))\b",
    re.IGNORECASE,
)


def _run_git(repo_root: Path, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "git not installed"


# ─── git_blame_function ──────────────────────────────────────────────────────

def git_blame_function(
    repo_root: Path, file_rel: str, line_start: int, line_end: int,
) -> dict:
    """Return blame info for each line in [start, end] of a file.

    Output: list of {line, sha, author, ts, summary, blame_text}.
    Useful for the validator to ask "who added this check and when?"
    """
    full_path = repo_root / file_rel
    if not full_path.exists():
        return {"error": f"file not found: {file_rel}"}
    rc, out, err = _run_git(repo_root, [
        "blame", "-L", f"{line_start},{line_end}", "--porcelain", file_rel,
    ])
    if rc != 0:
        return {"error": f"blame failed: {err.strip()[:200]}"}
    entries: list[dict] = []
    cur: dict = {}
    for line in out.splitlines():
        if not line:
            continue
        if line.startswith("\t"):
            # The blame_text for the current entry
            cur["blame_text"] = line[1:][:200]
            entries.append(cur)
            cur = {}
            continue
        parts = line.split(" ", 1)
        key = parts[0]
        val = parts[1] if len(parts) > 1 else ""
        if re.match(r"^[0-9a-f]{40}", key) and "line" not in cur:
            cur["sha"] = key
            sub = val.split(" ")
            if len(sub) >= 2:
                cur["line"] = int(sub[1])
        elif key == "author":
            cur["author"] = val
        elif key == "author-time":
            cur["ts"] = int(val) if val.isdigit() else val
        elif key == "summary":
            cur["summary"] = val[:120]
    return {
        "summary": f"{len(entries)} blame entries for {file_rel}:{line_start}-{line_end}",
        "handles": entries,
    }


# ─── recent_security_commits ─────────────────────────────────────────────────

def recent_security_commits(
    repo_root: Path, days: int = 365, limit: int = 50,
) -> dict:
    """Commits in the last N days whose messages match security keywords."""
    rc, out, _ = _run_git(repo_root, [
        "log", f"--since={days}.days.ago", "--pretty=format:%H%x09%an%x09%at%x09%s",
        "-n", "5000",
    ])
    if rc != 0:
        return {"error": "git log failed"}
    matches: list[dict] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        sha, author, ts, subject = parts
        if SECURITY_RELEVANT_KEYWORDS.search(subject):
            # Also fetch the changed files for this commit (cheap)
            rc2, out2, _ = _run_git(repo_root, [
                "show", "--name-only", "--pretty=format:", sha,
            ])
            files_changed = [l for l in out2.splitlines() if l.strip()]
            matches.append({
                "sha": sha[:12], "author": author,
                "ts": int(ts) if ts.isdigit() else ts,
                "subject": subject[:140],
                "files_changed": files_changed[:20],
            })
            if len(matches) >= limit:
                break
    return {
        "summary": f"{len(matches)} security-relevant commits in last {days}d",
        "handles": matches,
    }


# ─── function_change_history ─────────────────────────────────────────────────

def function_change_history(
    repo_root: Path, file_rel: str, line: int, context_lines: int = 30,
) -> dict:
    """All commits that modified the code around (file:line).

    Uses `git log -L` which tracks a line range across renames.
    """
    line_start = max(1, line - context_lines // 2)
    line_end = line + context_lines // 2
    rc, out, _ = _run_git(repo_root, [
        "log", f"-L{line_start},{line_end}:{file_rel}",
        "--pretty=format:%H%x09%an%x09%at%x09%s",
        "--no-patch", "-n", "100",
    ], timeout=120)
    if rc != 0:
        return {"error": "git log -L failed (file may not be tracked)"}
    commits: list[dict] = []
    for line_ in out.splitlines():
        parts = line_.split("\t")
        if len(parts) < 4:
            continue
        sha, author, ts, subject = parts
        commits.append({
            "sha": sha[:12], "author": author,
            "ts": int(ts) if ts.isdigit() else ts,
            "subject": subject[:140],
            "security_relevant": bool(SECURITY_RELEVANT_KEYWORDS.search(subject)),
        })
    return {
        "summary": f"{len(commits)} commits touching {file_rel}:{line} ± "
                    f"{context_lines // 2} lines",
        "handles": commits,
    }


# ─── removed_code_in_last_N_days ─────────────────────────────────────────────

def removed_code_in_last_n_days(
    repo_root: Path, days: int = 90, limit: int = 100,
) -> dict:
    """Code removed in the last N days. Deletions can be evidence of fixes
    or of regressions. Mythos-style: deletions are clues.
    """
    rc, out, _ = _run_git(repo_root, [
        "log", f"--since={days}.days.ago", "-p", "--no-merges",
        "--unified=0", "--pretty=format:%n=== COMMIT %H %an %s ===",
    ], timeout=180)
    if rc != 0:
        return {"error": "git log -p failed"}
    deletions: list[dict] = []
    current_commit = None
    current_file = None
    for raw in out.splitlines():
        if raw.startswith("=== COMMIT "):
            m = re.match(r"=== COMMIT (\w+) (\S+) (.*) ===", raw)
            if m:
                current_commit = {
                    "sha": m.group(1)[:12], "author": m.group(2),
                    "subject": m.group(3)[:140],
                }
            continue
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
            continue
        if raw.startswith("- ") and not raw.startswith("--- ") and current_commit \
                and current_file:
            deleted_text = raw[1:].rstrip()
            if not deleted_text.strip():
                continue
            deletions.append({
                "file": current_file,
                "removed_text": deleted_text[:200],
                "sha": current_commit["sha"],
                "subject": current_commit["subject"],
                "security_relevant": bool(
                    SECURITY_RELEVANT_KEYWORDS.search(current_commit["subject"])
                ),
            })
            if len(deletions) >= limit:
                break
    # Interesting deletions: those whose removed_text looks like security-relevant code
    interesting = [
        d for d in deletions
        if re.search(
            r"\b(if|check|verify|validate|sanitiz|escape|csrf|auth|allowlist|"
            r"denylist|assert)\b", d["removed_text"], re.IGNORECASE,
        )
    ]
    return {
        "summary": f"{len(deletions)} deletions in last {days}d; "
                    f"{len(interesting)} look security-relevant",
        "handles": deletions[:50],
        "facets": {"interesting_deletions": interesting[:20]},
    }


# ─── commit_message_search ───────────────────────────────────────────────────

def commit_message_search(
    repo_root: Path, pattern: str, limit: int = 50,
) -> dict:
    """Find commits whose message matches a custom regex."""
    rc, out, _ = _run_git(repo_root, [
        "log", "--all", "-iE", "--grep", pattern,
        "--pretty=format:%H%x09%an%x09%at%x09%s",
        "-n", str(limit),
    ])
    if rc != 0:
        return {"error": "git log --grep failed"}
    matches = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        sha, author, ts, subject = parts
        matches.append({
            "sha": sha[:12], "author": author,
            "ts": int(ts) if ts.isdigit() else ts,
            "subject": subject[:140],
        })
    return {
        "summary": f"{len(matches)} commits match /{pattern}/",
        "handles": matches,
    }
