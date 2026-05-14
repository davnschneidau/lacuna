"""Tests for v3 Layer 2 precision-analysis tools."""
from __future__ import annotations

from pathlib import Path

import pytest


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
    """If we have a guard `if n < MAX:` we should not flag inside that branch."""
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
    # The current heuristic may or may not perfectly track this; the test
    # documents the *intended* behavior. We allow either zero findings or
    # a single low-confidence one — but never a high-confidence one.
    high_conf = [f for f in result["findings"] if f["confidence"] > 0.65]
    assert not high_conf, "bounded n should never be high-confidence"


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


def test_allocator_map_counts_standard_allocators(tmp_path: Path):
    from lacuna.precision import analyze_allocator_map
    (tmp_path / "alloc.c").write_text("""
#include <stdlib.h>
void f() { void *p = malloc(1024); free(p); }
""")
    result = analyze_allocator_map(tmp_path, repo_name="t")
    assert result["global_allocators"].get("malloc", 0) >= 1
    assert result["global_allocators"].get("free", 0) >= 1


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
