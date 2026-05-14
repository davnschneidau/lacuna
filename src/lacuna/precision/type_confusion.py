"""
Type-confusion detector.

For every cast, type assertion, or coercion across a trust boundary,
check whether the runtime type is statically guaranteed. The "trust
boundary" matters — type assertions on locally-constructed objects are
safe; type assertions on JSON-deserialized data are not.

Languages and patterns:

  C/C++:    static_cast / reinterpret_cast / dynamic_cast — flag if cast
            target is a pointer that came from network/file read.

  Java:     `((T) obj)` cast immediately following deserialization
            (ObjectInputStream.readObject, Jackson readValue without
            type-binding). The unsafe pattern.

  TypeScript: `as T` without a corresponding type guard, especially when
            T is more specific than the source.

  Python:   `pickle.loads(x).attr` — using deserialized object without
            isinstance check is a CWE-843 hazard.

  Go:       `x.(T)` without the `, ok` form on interface{} from JSON.

  C#:       Pattern matching with object → derived without `is` check.

This analyzer is heuristic: it surfaces *candidates* for hunters/validators
to investigate. False-positive rate is moderate; that's why it's a
precision finding, not a hypothesis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)

SUFFIX_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".java": "java", ".py": "python",
    ".go": "go", ".js": "javascript", ".ts": "typescript",
    ".cs": "csharp", ".rb": "ruby",
}

# Source patterns: where the suspect data comes FROM
DESERIAL_SOURCES = re.compile(
    r"\bpickle\.loads?\b|\bMarshal\.load\b|\bunserialize\b|"
    r"\bObjectInputStream\b|\.readObject\b|\byaml\.load\b|"
    r"\bjson\.loads?\b|\bJSON\.parse\b|"
    r"\breadValue\b|\bDeserialize\b|\bunmarshal\b|"
    r"\bFromJson\b"
)

# C/C++: reinterpret/static_cast on network/file-read pointers
CPP_CAST_RE = re.compile(
    r"\b(reinterpret_cast|static_cast|dynamic_cast)\s*<"
)

# Java cast pattern
JAVA_CAST_RE = re.compile(r"\(\s*([A-Z]\w+)\s*\)\s*(\w+)")

# Go type assertion without `, ok`
GO_TYPE_ASSERT_RE = re.compile(r"\b(\w+)\.\(([A-Z]\w+)\)")
GO_TYPE_ASSERT_OK_RE = re.compile(r"\b\w+,\s*\w+\s*:?=\s*\w+\.\([A-Z]\w+\)")

# TS `as` assertion
TS_AS_RE = re.compile(r"\bas\s+([A-Z]\w+)\b")


@dataclass
class Finding:
    kind: str
    repo: str
    file: str
    line: int
    function_qual: str | None
    cwe: str
    detail_md: str
    evidence: dict
    confidence: float


def analyze(repo_root: Path, repo_name: str | None = None,
            max_files: int = 5000) -> dict:
    repo_name = repo_name or repo_root.name
    findings: list[Finding] = []
    files_scanned = 0

    for p in repo_root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not p.is_file() or SKIP.search(str(p)):
            continue
        lang = SUFFIX_TO_LANG.get(p.suffix.lower())
        if not lang:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        try:
            rel = str(p.relative_to(repo_root))
            if lang == "python":
                _analyze_python(text, rel, repo_name, findings)
            elif lang == "java":
                _analyze_java(text, rel, repo_name, findings)
            elif lang in ("cpp", "c"):
                _analyze_cpp(text, rel, repo_name, lang, findings)
            elif lang == "go":
                _analyze_go(text, rel, repo_name, findings)
            elif lang in ("typescript",):
                _analyze_ts(text, rel, repo_name, findings)
        except Exception:
            continue

    return {
        "summary": (
            f"type_confusion: {len(findings)} findings across "
            f"{files_scanned} files"
        ),
        "findings": [_to_dict(f) for f in findings],
    }


# ─── Per-language analyzers ─────────────────────────────────────────────────


def _line_window(text: str, byte_offset: int, before: int = 5) -> str:
    """Return `before` lines preceding the byte offset, joined."""
    pre = text[:byte_offset]
    lines = pre.splitlines()
    return "\n".join(lines[-before:])


def _analyze_python(text: str, file: str, repo: str,
                    out: list[Finding]) -> None:
    """Python: pickle.loads/json.loads result used without isinstance check."""
    # Pattern: var = pickle.loads(...) ... var.attr or var[i] without
    # isinstance(var, T) preceding.
    for m in re.finditer(
        r"^\s*(\w+)\s*=\s*([\w\.]+)\(",
        text, re.MULTILINE,
    ):
        var, callee = m.group(1), m.group(2)
        if not DESERIAL_SOURCES.search(callee):
            continue
        # Look for use of var in the next 30 lines
        after = text[m.end():m.end() + 3000]
        # Is there an isinstance(var, ...) check before any use?
        first_use_match = re.search(rf"\b{re.escape(var)}\.(\w+)|"
                                      rf"\b{re.escape(var)}\[",
                                      after)
        if not first_use_match:
            continue
        before_use = after[:first_use_match.start()]
        if re.search(rf"\bisinstance\s*\(\s*{re.escape(var)}\b", before_use):
            continue
        # Suspect use without check
        line_no = text[:m.start()].count("\n") + 1
        use_line_no = line_no + before_use.count("\n") + 1
        out.append(Finding(
            kind="type_confusion",
            repo=repo, file=file, line=use_line_no,
            function_qual=None,
            cwe="CWE-843",
            detail_md=(
                f"`{var}` is deserialized via `{callee}(...)` at line "
                f"{line_no} and used at line {use_line_no} without an "
                f"intervening `isinstance({var}, T)` check. If the "
                f"deserialized payload can be attacker-controlled, "
                f"the type assumption is wrong."
            ),
            evidence={
                "var": var, "source_call": callee,
                "source_line": line_no, "use_line": use_line_no,
            },
            confidence=0.55,
        ))


def _analyze_java(text: str, file: str, repo: str,
                  out: list[Finding]) -> None:
    """Java: explicit casts following a deserialization.

    Finds *every* cast in the window after a deserialize call, not just
    the first. A single ``readObject`` is often immediately followed by
    multiple casts (one per field accessed); each is independently a
    CWE-843 hazard if not guarded.
    """
    for m in DESERIAL_SOURCES.finditer(text):
        deserial_line_no = text[:m.start()].count("\n") + 1
        window = text[m.start():m.start() + 600]
        for cast_match in JAVA_CAST_RE.finditer(window):
            target_type = cast_match.group(1)
            # If the cast is wrapped in an ``instanceof`` guard for the
            # same target type anywhere in the window, treat it as safe.
            if re.search(
                rf"\binstanceof\s+{re.escape(target_type)}\b", window,
            ):
                continue
            cast_line = (
                deserial_line_no + window[:cast_match.start()].count("\n")
            )
            out.append(Finding(
                kind="type_confusion",
                repo=repo, file=file, line=cast_line,
                function_qual=None,
                cwe="CWE-843",
                detail_md=(
                    f"Cast to `{target_type}` follows a deserialize "
                    f"operation at line {deserial_line_no} without an "
                    f"`instanceof` guard. If the deserialized stream is "
                    f"attacker-controlled, the cast may produce a "
                    f"`ClassCastException` at best, and a confused-type "
                    f"read/write at worst."
                ),
                evidence={
                    "cast_target": target_type,
                    "source_line": deserial_line_no,
                    "cast_line": cast_line,
                },
                confidence=0.6,
            ))


_CPP_BUFFER_NAMES = (
    "buf", "buffer", "data", "msg", "message", "pkt", "pkt_buf", "packet",
    "payload", "body", "input", "raw", "bytes", "chunk", "frame", "rx",
    "tx", "stream", "header", "hdr",
)
_CPP_BUFFER_PAT = re.compile(
    r">\s*\(\s*(" + "|".join(_CPP_BUFFER_NAMES) + r")\b",
)


def _analyze_cpp(text: str, file: str, repo: str, lang: str,
                 out: list[Finding]) -> None:
    """C/C++: reinterpret_cast and static_cast on buffer-derived pointers."""
    for m in CPP_CAST_RE.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        tail = text[m.start():m.start() + 300]
        if _CPP_BUFFER_PAT.search(tail):
            cast_kind = m.group(1)
            out.append(Finding(
                kind="type_confusion",
                repo=repo, file=file, line=line_no,
                function_qual=None,
                cwe="CWE-843",
                detail_md=(
                    f"`{cast_kind}` on what looks like a buffer-derived "
                    f"pointer at {file}:{line_no}. If the buffer is "
                    f"attacker-controlled, the resulting object's fields "
                    f"will be attacker-controlled at arbitrary alignment, "
                    f"enabling memory disclosure and corruption."
                ),
                evidence={
                    "cast_kind": cast_kind, "language": lang,
                },
                confidence=0.6,
            ))


def _analyze_go(text: str, file: str, repo: str,
                out: list[Finding]) -> None:
    """Go: type assertion `x.(T)` without `, ok` form, on json.Unmarshal output."""
    # Find every type assertion
    for m in GO_TYPE_ASSERT_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line = text[line_start:text.find("\n", m.start())]
        if GO_TYPE_ASSERT_OK_RE.match(line):
            continue
        # Skip the `, ok` form
        # Look backward for a recent json.Unmarshal / Decode
        window_before = text[max(0, m.start() - 800):m.start()]
        if re.search(r"json\.(Unmarshal|Decode)|json\.NewDecoder",
                     window_before):
            line_no = text[:m.start()].count("\n") + 1
            out.append(Finding(
                kind="type_confusion",
                repo=repo, file=file, line=line_no,
                function_qual=None,
                cwe="CWE-843",
                detail_md=(
                    f"Type assertion `{m.group(1)}.({m.group(2)})` at "
                    f"{file}:{line_no} uses the panic-on-fail form. If "
                    f"the upstream interface{{}} came from JSON decode, "
                    f"a crafted payload causes a runtime panic (DoS) or "
                    f"unexpected execution path."
                ),
                evidence={
                    "var": m.group(1), "target_type": m.group(2),
                },
                confidence=0.6,
            ))


_TS_AS_PATTERNS = (
    # JSON.parse(...) as T
    re.compile(r"JSON\.parse\s*\([^)]*\)\s*as\s+([A-Z]\w+)"),
    # fetch(...).then(r => r.json()) as T
    re.compile(
        r"\.then\s*\(\s*\w+\s*=>\s*\w+\.json\s*\(\s*\)\s*\)\s*as\s+([A-Z]\w+)"
    ),
    # await req.json() as T  /  await response.json() as T
    re.compile(r"await\s+[\w.]*?\.json\s*\(\s*\)\s*as\s+([A-Z]\w+)"),
    # await fetch(...).then(...) as T
    re.compile(
        r"await\s+fetch\s*\([^)]*\)\.\w+\([^)]*\)\s*as\s+([A-Z]\w+)"
    ),
)


def _analyze_ts(text: str, file: str, repo: str,
                out: list[Finding]) -> None:
    """TypeScript: ``as T`` without a corresponding type guard.

    Covers the three common shapes for runtime-unchecked casts:
      * ``JSON.parse(x) as T``
      * ``fetch(...).then(r => r.json()) as T``
      * ``await req.json() as T``
    """
    seen: set[int] = set()
    for pat in _TS_AS_PATTERNS:
        for m in pat.finditer(text):
            if m.start() in seen:
                continue
            seen.add(m.start())
            line_no = text[:m.start()].count("\n") + 1
            out.append(Finding(
                kind="type_confusion",
                repo=repo, file=file, line=line_no,
                function_qual=None,
                cwe="CWE-843",
                detail_md=(
                    f"`{m.group(0)}` at {file}:{line_no}. TypeScript's "
                    f"`as` is unchecked at runtime. If the input is "
                    f"attacker-controlled, downstream code may "
                    f"dereference undefined fields or behave "
                    f"unexpectedly. Prefer a Zod/Yup/io-ts schema "
                    f"validation."
                ),
                evidence={"cast_target": m.group(1)},
                confidence=0.55,
            ))


def _to_dict(f: Finding) -> dict:
    return {
        "kind": f.kind, "repo": f.repo, "file": f.file, "line": f.line,
        "function_qual": f.function_qual, "cwe": f.cwe,
        "detail_md": f.detail_md, "evidence": f.evidence,
        "confidence": f.confidence,
    }
