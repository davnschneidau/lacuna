"""
Test corpus analyzer.

Endpoints with no tests get extra hunter attention. Auth flows tested only
on the happy path get higher-confidence hypotheses. The principle: tests
encode developer intent. The negative space (untested paths) is the most
fertile ground for bugs.

Tools:
  test_coverage_for_endpoint  — does this route/handler have tests?
  test_assertions_for_function — what asserts exist for this function?
  untested_handlers           — handlers with no corresponding tests
"""
from __future__ import annotations

import re
from pathlib import Path

# Files matching these patterns are considered test files
TEST_FILE_PATTERNS = re.compile(
    r"(^|/)(test_[\w]+\.py|[\w]+_test\.py|tests?/.*\.py|"
    r"[\w]+\.(test|spec)\.[jt]sx?|"
    r"[\w]+\.(test|spec)\.go|"
    r".*Test\.java)$"
)

ASSERT_PATTERNS = re.compile(
    r"\bassert\b|\.assert(Equal|True|False|In|NotIn|Raises|Contains)|"
    r"\bexpect\(|\bshould\.|\bShould\.|\bShouldEqual|\.Equal\(|\.NotNil\("
)


def _iter_test_files(repo_root: Path) -> list[Path]:
    return [
        p for p in repo_root.rglob("*")
        if p.is_file() and TEST_FILE_PATTERNS.search(str(p))
    ]


def test_coverage_for_endpoint(repo_root: Path, route: str) -> dict:
    """Heuristic: do any test files reference this route literally?

    Returns a list of test files mentioning the route + the assertion count
    near each mention.
    """
    test_files = _iter_test_files(repo_root)
    hits: list[dict] = []
    escaped = re.escape(route)
    for tf in test_files:
        try:
            text = tf.read_text(errors="ignore")
        except OSError:
            continue
        for m in re.finditer(escaped, text):
            # Count asserts in a 50-line window around the match
            start = max(0, text.count("\n", 0, m.start()) - 25)
            end = start + 50
            lines = text.splitlines()[start:end]
            assert_count = sum(
                1 for ln in lines if ASSERT_PATTERNS.search(ln)
            )
            hits.append({
                "test_file": str(tf.relative_to(repo_root)),
                "line": text.count("\n", 0, m.start()) + 1,
                "assertion_window_count": assert_count,
            })
    return {
        "summary": f"route {route!r} referenced in {len(hits)} test locations",
        "covered": len(hits) > 0,
        "handles": hits,
    }


def test_assertions_for_function(
    repo_root: Path, function_name: str,
) -> dict:
    """Find all test sites that invoke a function by name AND have asserts nearby."""
    test_files = _iter_test_files(repo_root)
    hits: list[dict] = []
    fn_pat = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for tf in test_files:
        try:
            text = tf.read_text(errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if fn_pat.search(line):
                # Window of asserts around this call
                window = "\n".join(lines[max(0, i - 5):i + 10])
                asserts = ASSERT_PATTERNS.findall(window)
                hits.append({
                    "test_file": str(tf.relative_to(repo_root)),
                    "line": i + 1,
                    "snippet": line.strip()[:200],
                    "assert_count_nearby": len(asserts),
                })
    return {
        "summary": f"{function_name} appears in {len(hits)} test sites",
        "handles": hits,
    }


def untested_handlers(repo_root: Path, handler_routes: list[str]) -> dict:
    """Given a list of handler routes (from recon's entrypoints), return
    those that have NO references in any test file.
    """
    test_files = _iter_test_files(repo_root)
    all_test_text = "\n".join(
        tf.read_text(errors="ignore") for tf in test_files
    )
    untested: list[dict] = []
    tested: list[dict] = []
    for route in handler_routes:
        if re.escape(route) in all_test_text or route in all_test_text:
            tested.append({"route": route})
        else:
            untested.append({"route": route})
    return {
        "summary": f"{len(untested)} of {len(handler_routes)} handlers appear untested",
        "facets": {
            "untested_count": len(untested),
            "tested_count": len(tested),
        },
        "handles": untested[:100],
    }
