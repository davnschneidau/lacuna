"""Tests for v3 Layer 2 precision-analysis tools."""
from __future__ import annotations

from pathlib import Path

import pytest


# Lifetime / format-string / type-confusion / allocator-map all operate on
# C/Java/Go via tree-sitter. The Python-only tests obviously don't need
# it. The C/C++ tests are gated below with importorskip.
def _have_tree_sitter() -> bool:
    try:
        import tree_sitter_language_pack  # noqa: F401
        return True
    except ImportError:
        try:
            import tree_sitter_languages  # noqa: F401
            return True
        except ImportError:
            return False


needs_tree_sitter = pytest.mark.skipif(
    not _have_tree_sitter(),
    reason="tree-sitter-language-pack not installed; C/C++ analyzers can't parse",
)


# ─── integer_range ─────────────────────────────────────────────────────────


def test_integer_range_catches_python_bytearray_overflow(tmp_path: Path):
    from lacuna.precision import analyze_integer_range
    (tmp_path / "vuln.py").write_text("""
from flask import request
def handler():
    n = int(request.args.get("n"))
    buf = bytearray(n)
    return "ok"
""")
    result = analyze_integer_range(tmp_path, repo_name="t")
    assert result["findings"], "should catch bytearray(n) with attacker-controlled n"
    assert any(f["cwe"] in ("CWE-190", "CWE-789") for f in result["findings"])


def test_integer_range_skips_safe_constant_size(tmp_path: Path):
    from lacuna.precision import analyze_integer_range
    (tmp_path / "safe.py").write_text("""
def make_buf():
    return bytearray(1024)
""")
    result = analyze_integer_range(tmp_path, repo_name="t")
    assert not result["findings"], "constant size is safe"


def test_integer_range_skips_bounded_attacker_input(tmp_path: Path):
    """With a real bound check, integer_range must produce *no* finding."""
    from lacuna.precision import analyze_integer_range
    (tmp_path / "safe.py").write_text("""
from flask import request
def handler():
    n = int(request.args.get("n"))
    if n < 1024:
        b = bytearray(n)
    return "ok"
""")
    result = analyze_integer_range(tmp_path, repo_name="t")
    assert not result["findings"], (
        "bound check `if n < 1024` must fully suppress the finding; "
        f"got {result['findings']!r}"
    )


# ─── format_string ─────────────────────────────────────────────────────────


def test_format_string_catches_python_logger(tmp_path: Path):
    from lacuna.precision import analyze_format_string
    (tmp_path / "vuln.py").write_text("""
import logging
logger = logging.getLogger(__name__)

def handler(user_input):
    logger.info(user_input)
""")
    result = analyze_format_string(tmp_path, repo_name="t")
    assert result["findings"]
    assert any(f["cwe"] == "CWE-117" for f in result["findings"])


def test_format_string_skips_literal_args(tmp_path: Path):
    from lacuna.precision import analyze_format_string
    (tmp_path / "safe.py").write_text("""
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.info("safe literal")
""")
    result = analyze_format_string(tmp_path, repo_name="t")
    assert not result["findings"]


# ─── type_confusion ───────────────────────────────────────────────────────


def test_type_confusion_catches_pickle_then_access(tmp_path: Path):
    from lacuna.precision import analyze_type_confusion
    (tmp_path / "vuln.py").write_text("""
import pickle
def handler(data):
    obj = pickle.loads(data)
    return obj.name
""")
    result = analyze_type_confusion(tmp_path, repo_name="t")
    assert result["findings"]
    assert any(f["cwe"] == "CWE-843" for f in result["findings"])


def test_type_confusion_skips_isinstance_guarded(tmp_path: Path):
    from lacuna.precision import analyze_type_confusion
    (tmp_path / "safe.py").write_text("""
import pickle
def handler(data):
    obj = pickle.loads(data)
    if isinstance(obj, dict):
        return obj.get("name")
    return None
""")
    result = analyze_type_confusion(tmp_path, repo_name="t")
    # The isinstance check before access should suppress the finding
    assert not result["findings"]


# ─── allocator_map ─────────────────────────────────────────────────────────


@needs_tree_sitter
def test_allocator_map_counts_standard_allocators(tmp_path: Path):
    from lacuna.precision import analyze_allocator_map
    (tmp_path / "alloc.c").write_text("""
#include <stdlib.h>
void f() { void *p = malloc(1024); free(p); }
""")
    result = analyze_allocator_map(tmp_path, repo_name="t")
    assert result["global_allocators"].get("malloc", 0) >= 1
    assert result["global_allocators"].get("free", 0) >= 1


@needs_tree_sitter
def test_allocator_map_finds_custom_pairs(tmp_path: Path):
    from lacuna.precision import analyze_allocator_map
    (tmp_path / "pool.c").write_text("""
static void *pkt_alloc(size_t n) { return NULL; }
static void pkt_free(void *p) { (void)p; }
void g() { void *q = pkt_alloc(64); pkt_free(q); }
""")
    result = analyze_allocator_map(tmp_path, repo_name="t")
    assert any(
        c["alloc_fn"] == "pkt_alloc" and c["free_fn"] == "pkt_free"
        for c in result["custom_pairs"]
    )


# ─── lifetime ─────────────────────────────────────────────────────────────


@needs_tree_sitter
def test_lifetime_catches_straight_line_uaf(tmp_path: Path):
    """The textbook case: free(p); then dereference p."""
    from lacuna.precision import analyze_lifetime
    (tmp_path / "uaf.c").write_text("""
#include <stdlib.h>
#include <string.h>

int handler(const char *src) {
    char *p = malloc(64);
    if (!p) return -1;
    strcpy(p, src);
    free(p);
    return p[0];          /* use-after-free */
}
""")
    result = analyze_lifetime(tmp_path, repo_name="t")
    uaf = [
        f for f in result["findings"]
        if f.get("cwe") in ("CWE-416", "CWE-415")
    ]
    assert uaf, (
        "straight-line free/use must produce a CWE-416 finding; "
        f"got {result['findings']!r}"
    )


@needs_tree_sitter
def test_lifetime_branch_aware_only_one_arm_frees(tmp_path: Path):
    """When free() is in only one branch, the analyzer should not call a
    use after the join site a UAF — the other branch never freed."""
    from lacuna.precision import analyze_lifetime
    (tmp_path / "branch.c").write_text("""
#include <stdlib.h>

int handler(int flag) {
    char *p = malloc(64);
    if (!p) return -1;
    if (flag) {
        /* freed only in this arm */
        free(p);
        return 0;
    }
    return p[0];        /* safe — fall-through arm never freed */
}
""")
    result = analyze_lifetime(tmp_path, repo_name="t")
    uaf = [
        f for f in result["findings"]
        if f.get("cwe") in ("CWE-416", "CWE-415")
    ]
    assert not uaf, (
        "branch-aware lifetime tracking must not flag the post-branch use "
        "when free() is only on the other arm; got "
        f"{result['findings']!r}"
    )


@needs_tree_sitter
def test_lifetime_null_after_free_suppresses_finding(tmp_path: Path):
    """Setting the pointer to NULL after free is the standard defense — a
    subsequent dereference is still a bug, but in this function the
    pointer is set to NULL and never used again, so no UAF should be
    reported."""
    from lacuna.precision import analyze_lifetime
    (tmp_path / "null.c").write_text("""
#include <stdlib.h>

void handler(void) {
    char *p = malloc(64);
    if (!p) return;
    free(p);
    p = NULL;
    /* no use afterwards */
}
""")
    result = analyze_lifetime(tmp_path, repo_name="t")
    uaf = [
        f for f in result["findings"]
        if f.get("cwe") in ("CWE-416", "CWE-415")
    ]
    assert not uaf, (
        "NULL-after-free with no subsequent use must not produce a UAF "
        f"finding; got {result['findings']!r}"
    )
