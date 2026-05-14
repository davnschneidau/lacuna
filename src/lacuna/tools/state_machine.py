"""
State machine extraction for stateful flows.

For password reset, OAuth, multi-step checkout — derive a probable FSM from
the codebase by analyzing route handlers and looking at what they read/write
in session storage, what conditions they check, and where they redirect.

Output:
  - states: distinct values of a session field (e.g. session['reset_step']
            ∈ {'init','code_sent','code_verified','password_set'})
  - transitions: handler routes that change a state
  - suspected_invariant_breaks: states that handlers can be entered from
            without proper precondition checks
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path


SESSION_WRITE_PATTERNS = re.compile(
    r"""session\[['"](\w+)['"]\]\s*=\s*['"]?(\w+)['"]?|"""
    r"""session\.(\w+)\s*=\s*['"]?(\w+)['"]?|"""
    r"""req\.session\.(\w+)\s*=\s*['"]?(\w+)['"]?"""
)

SESSION_READ_PATTERNS = re.compile(
    r"""session\[['"](\w+)['"]\]|session\.get\(['"](\w+)['"]\)|"""
    r"""req\.session\.(\w+)"""
)

ROUTE_PATTERNS = re.compile(
    r"""@(?:app|router|bp|blueprint)\.\w+\(['"]([^'"]+)['"]|"""
    r"""@(?:Get|Post|Put|Delete|Patch)Mapping\(['"]([^'"]+)['"]|"""
    r"""(?:app|router)\.(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]"""
)

REDIRECT_PATTERNS = re.compile(
    r"""redirect\(['"]([^'"]+)['"]|res\.redirect\(['"]([^'"]+)['"]|"""
    r"""return\s+redirect\(['"]([^'"]+)['"]"""
)

# Skip these paths during scanning
SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)


def extract_state_machine(repo_root: Path) -> dict:
    states_by_field: dict[str, set[str]] = defaultdict(set)
    transitions: list[dict] = []
    handlers_by_route: dict[str, list[dict]] = defaultdict(list)
    suspected_invariant_breaks: list[dict] = []

    suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".java"}
    for p in repo_root.rglob("*"):
        if not p.is_file() or SKIP.search(str(p)) or p.suffix.lower() not in suffixes:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()

        # Find route handlers and their bodies (heuristic — look in a 30-line window after route decorator)
        for i, line in enumerate(lines):
            rm = ROUTE_PATTERNS.search(line)
            if not rm:
                continue
            route = (rm.group(1) or rm.group(2) or rm.group(3) or "").strip()
            window = "\n".join(lines[i:i + 60])

            # Detect session reads in handler
            reads = set()
            for m in SESSION_READ_PATTERNS.finditer(window):
                field = m.group(1) or m.group(2) or m.group(3)
                if field:
                    reads.add(field)

            # Detect session writes (state transitions)
            writes: list[tuple[str, str]] = []
            for m in SESSION_WRITE_PATTERNS.finditer(window):
                field = m.group(1) or m.group(3) or m.group(5)
                value = m.group(2) or m.group(4) or m.group(6)
                if field and value:
                    writes.append((field, value))
                    states_by_field[field].add(value)

            # Detect redirects
            redirects = []
            for m in REDIRECT_PATTERNS.finditer(window):
                target = m.group(1) or m.group(2) or m.group(3)
                if target:
                    redirects.append(target)

            handler_info = {
                "route": route,
                "file": str(p.relative_to(repo_root)),
                "line": i + 1,
                "session_reads": sorted(reads),
                "session_writes": writes,
                "redirects": redirects,
            }
            handlers_by_route[route].append(handler_info)
            for field, value in writes:
                transitions.append({
                    "field": field, "to_state": value,
                    "via_route": route, "via_file": str(p.relative_to(repo_root)),
                    "via_line": i + 1,
                    "preconditions_checked": sorted(reads),
                })

    # Heuristic invariant detection — if a handler writes state X but didn't
    # read the prior state X' first, the precondition may be missing
    seen_field_values: dict[str, list[str]] = {
        f: sorted(vs) for f, vs in states_by_field.items()
    }
    for t in transitions:
        f = t["field"]
        # If multiple possible prior states exist for this field but the
        # handler doesn't check any, flag it
        if len(seen_field_values.get(f, [])) >= 2 \
                and f not in t["preconditions_checked"]:
            suspected_invariant_breaks.append({
                "field": f,
                "transitions_to": t["to_state"],
                "via_route": t["via_route"],
                "via_file": t["via_file"],
                "via_line": t["via_line"],
                "note": (
                    f"writes {f}={t['to_state']} but does not first check "
                    f"the current value of {f}; possible state-skip vuln."
                ),
            })

    nodes = [
        {"field": f, "states": sorted(vs)}
        for f, vs in states_by_field.items()
    ]
    return {
        "summary": (
            f"extracted FSM: {len(nodes)} stateful fields, "
            f"{len(transitions)} transitions, "
            f"{len(suspected_invariant_breaks)} suspected invariant breaks"
        ),
        "nodes": nodes,
        "transitions": transitions[:200],
        "suspected_invariant_breaks": suspected_invariant_breaks[:50],
    }
