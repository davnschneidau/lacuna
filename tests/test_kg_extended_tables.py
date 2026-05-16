"""Tests for KG extended tables and their client methods."""
from __future__ import annotations

# ─── precision_findings ─────────────────────────────────────────────────────


def test_add_and_list_precision_findings(tmp_kg):
    pf_id = tmp_kg.add_precision_finding(
        kind="int_overflow",
        repo="lib", file="parse.c", line=42,
        function_qual="parse_pkt", cwe="CWE-190",
        detail_md="malloc(n*sizeof) overflow", evidence={"n": "wire"},
        confidence=0.8,
    )
    assert pf_id.startswith("pf-")

    rows = tmp_kg.list_precision_findings(kind="int_overflow")
    assert len(rows) == 1
    assert rows[0]["cwe"] == "CWE-190"


def test_filter_precision_findings_by_repo(tmp_kg):
    tmp_kg.add_precision_finding(
        kind="uaf", repo="a", file="a.c", line=1,
        function_qual="f1", cwe="CWE-416",
        detail_md="x", evidence={}, confidence=0.6,
    )
    tmp_kg.add_precision_finding(
        kind="uaf", repo="b", file="b.c", line=1,
        function_qual="f2", cwe="CWE-416",
        detail_md="y", evidence={}, confidence=0.6,
    )
    assert len(tmp_kg.list_precision_findings(repo="a")) == 1
    assert len(tmp_kg.list_precision_findings(repo="b")) == 1


def test_mark_precision_finding_consumed(tmp_kg):
    pf = tmp_kg.add_precision_finding(
        kind="fmt_string", repo="r", file="f.c", line=1,
        function_qual="fn", cwe="CWE-134",
        detail_md="x", evidence={}, confidence=0.7,
    )
    assert len(tmp_kg.list_precision_findings(unconsumed_only=True)) == 1
    tmp_kg.mark_precision_finding_consumed(pf, "hyp-99")
    assert len(tmp_kg.list_precision_findings(unconsumed_only=True)) == 0
    assert len(tmp_kg.list_precision_findings()) == 1


# ─── sanitizer_builds ──────────────────────────────────────────────────────


def test_sanitizer_build_memoization(tmp_kg):
    sb_id = tmp_kg.record_sanitizer_build(
        repo="lib", git_sha="abc123", sanitizers="asan,ubsan",
        build_system="cmake", status="success",
        build_log_path="/tmp/log",
        binaries=[{"name": "libfoo.so", "path": "/tmp/libfoo.so"}],
        warnings=[], duration_s=120,
    )
    assert sb_id.startswith("sb-")
    row = tmp_kg.latest_sanitizer_build("lib", "abc123")
    assert row is not None
    assert row["status"] == "success"


def test_no_sanitizer_build_returns_none(tmp_kg):
    assert tmp_kg.latest_sanitizer_build("lib", "nonexistent") is None


# ─── fuzz_runs and fuzz_crashes ────────────────────────────────────────────


def test_fuzz_run_and_crash_roundtrip(tmp_kg):
    fr_id = tmp_kg.record_fuzz_run(
        repo="lib", function_qual="parse", binary_path="/tmp/x",
        timeout_s=300, executions=1_000_000, coverage_pct=42.0,
        status="crashed", triggered_by="hyp-1", duration_s=300,
    )
    c_id = tmp_kg.record_fuzz_crash(
        fuzz_run_id=fr_id, asan_kind="heap-buffer-overflow",
        crash_stack=["parse", "memcpy"], input_path="/tmp/c1",
        minimized_input_path="/tmp/c1.min", asan_log_path="/tmp/asan.log",
    )
    assert c_id.startswith("fc-")
    runs = tmp_kg.list_fuzz_runs_for_function("lib", "parse")
    assert len(runs) == 1
    crashes = tmp_kg.list_fuzz_crashes(fr_id)
    assert len(crashes) == 1
    assert crashes[0]["asan_kind"] == "heap-buffer-overflow"


# ─── patch_rules and variant_links ─────────────────────────────────────────


def test_patch_rules_roundtrip(tmp_kg):
    pr = tmp_kg.add_patch_rule(
        source_kind="internal_commit", source_ref="deadbeef",
        repo="lib", bug_class="CWE-89",
        rule_yaml="rules: [...]",
        before_pattern='execute("SELECT" + x)',
        after_pattern='execute("SELECT %s", x)',
        essence_md="SQL injection: concat replaced by parameterized.",
        confidence=0.7,
    )
    assert pr.startswith("pr-")
    rows = tmp_kg.list_patch_rules(source_kind="internal_commit")
    assert len(rows) == 1
    fetched = tmp_kg.get_patch_rule(pr)
    assert fetched["bug_class"] == "CWE-89"


def test_variant_links(tmp_kg):
    tmp_kg.add_variant_link("hyp-child-1", "fnd-parent", None)
    tmp_kg.add_variant_link("hyp-child-2", "fnd-parent", None)
    variants = tmp_kg.list_variants_of("fnd-parent")
    assert len(variants) == 2


# ─── differential_findings ─────────────────────────────────────────────────


def test_differential_finding_persist(tmp_kg):
    df = tmp_kg.add_differential_finding(
        protocol="http_request",
        input_hex="474554",
        parser_results={"nginx": {"ok": True}, "apache": {"ok": True}},
        divergence=True,
        exploit_class="http_request_smuggling",
    )
    assert df.startswith("df-")
