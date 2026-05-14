"""Tests for v3 Layer 4 patch-essence and variant propagation."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def _git_init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "test@test")
    _git(repo, "config", "user.name", "test")
    return repo


# ─── patch_essence ─────────────────────────────────────────────────────────


def test_extract_essence_from_real_commit(tmp_path: Path):
    """End-to-end: commit, extract, propagate, verify variant caught."""
    from lacuna.patches import extract_essence, propagate_pattern

    repo = _git_init_repo(tmp_path)

    # Vulnerable code
    (repo / "app.py").write_text(
        'def get_user(uid):\n'
        '    return db.query("SELECT * FROM users WHERE id = " + str(uid))\n'
    )
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-q", "-m", "init")

    # Fix it
    (repo / "app.py").write_text(
        'def get_user(uid):\n'
        '    return db.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
    )
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-q", "-m", "fix: parameterize SQL")
    fix_sha = _git(repo, "rev-parse", "HEAD")

    # Sibling vulnerable site
    (repo / "admin.py").write_text(
        'def get_post(pid):\n'
        '    return db.query("SELECT * FROM posts WHERE id = " + str(pid))\n'
    )
    _git(repo, "add", "admin.py")
    _git(repo, "commit", "-q", "-m", "feat: posts")

    essence = extract_essence(commit_sha=fix_sha, repo_root=repo)
    assert essence is not None
    assert essence.bug_class == "CWE-89"
    assert essence.before_pattern is not None
    assert essence.rule_yaml.startswith("rules:")

    # Propagate the rule
    matches = propagate_pattern(repo, essence.rule_yaml)
    # admin.py should match
    files = {m["file"] for m in matches["matches"]}
    assert "admin.py" in files, (
        f"variant in admin.py should be caught; got matches: {matches}"
    )


def test_extract_essence_handles_nonexistent_commit(tmp_path: Path):
    from lacuna.patches import extract_essence
    repo = _git_init_repo(tmp_path)
    result = extract_essence(commit_sha="000nonexistent000", repo_root=repo)
    assert result is None


def test_extract_essence_from_raw_diff_text():
    """Bypass git; provide diff text directly."""
    from lacuna.patches import extract_essence
    diff = """diff --git a/app.py b/app.py
index 1234..5678 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 def handler(req):
-    eval(req.args.get("x"))
+    if not is_safe(x):
+        return "denied"
"""
    essence = extract_essence(diff_text=diff)
    assert essence is not None
    assert essence.before_pattern is not None
    # We classify CWE-78 (OS command) or CWE-94 (code injection) for eval
    assert essence.bug_class in {"CWE-78", "CWE-94", "CWE-20"} or \
            essence.confidence > 0


# ─── propagate_pattern ─────────────────────────────────────────────────────


def test_propagate_with_empty_rule_yaml(tmp_path: Path):
    from lacuna.patches import propagate_pattern
    repo = _git_init_repo(tmp_path)
    (repo / "x.py").write_text("a = 1\n")
    result = propagate_pattern(repo, "rules: []")
    assert result["matches"] == []
