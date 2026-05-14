"""
Format-string sink detector.

Finds calls to format-interpreting functions where the format argument is
not a compile-time literal. Two bug shapes:

  1. Classic CWE-134: printf-family with non-literal format.
     `printf(user_input);`  ← attacker controls format directives → info
     leak / arbitrary write via %n.

  2. Logger-as-template (Log4Shell-style): logger functions whose
     implementation interprets the *message* (not just a format) for
     substitution patterns. Detected by:
       - Log4j-style: `logger.{info,debug,...}(non_literal)` on Java
         repos with log4j-core <= 2.14 on classpath.
       - Python: any logger call with non-literal that uses string
         formatting via % operator on the message.
       - Go: `log.Printf(non_literal, ...)` style.

We are deliberately conservative on the logger-as-template detection
to keep false-positive noise down. The dep-graph cross-reference (when
available) gates the high-severity classification.

Languages: C, C++, Java, Python, Go, JavaScript, Ruby.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from lacuna.flow.ast_parse import (
    Node, parse_python_file, parse_with_tree_sitter,
)

SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)

SUFFIX_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".java": "java", ".py": "python",
    ".go": "go", ".js": "javascript", ".ts": "typescript",
    ".rb": "ruby",
}

# printf-family identifiers — classic CWE-134
PRINTF_RE = re.compile(
    r"\b("
    r"printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|"
    r"vsnprintf|asprintf|vasprintf|"
    r"syslog|vsyslog|"
    r"fmt\.Printf|fmt\.Sprintf|fmt\.Fprintf|fmt\.Errorf|"
    r"log\.Printf|log\.Fatalf|log\.Panicf"
    r")\b"
)

# Logger calls — message-interpreting variants
JAVA_LOGGER_RE = re.compile(
    r"\blogger\.(info|debug|warn|error|fatal|trace)\b|"
    r"\bLOG\.(info|debug|warn|error|fatal|trace)\b|"
    r"\bLogger\.get(Logger|GlobalLogger)\b"
)
PY_LOGGER_RE = re.compile(
    r"\blogging\.(info|debug|warning|error|critical)\b|"
    r"\blog(?:ger)?\.(info|debug|warning|error|critical)\b"
)

# An argument is "non-literal" if it isn't a plain quoted string at the
# point of the call. tree-sitter's args strings include the surrounding
# delimiters when they ARE literals, so we look for the leading quote.
LITERAL_STR_RE = re.compile(r"""^\s*["'`].*["'`]\s*$""", re.DOTALL)


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
            languages: list[str] | None = None,
            dependency_hint: dict | None = None,
            max_files: int = 5000) -> dict:
    repo_name = repo_name or repo_root.name
    findings: list[Finding] = []
    files_scanned = 0

    # Optional cross-reference: did framework_detect find log4j-core <=2.14?
    log4j_vulnerable = False
    if dependency_hint:
        for dep, ver in dependency_hint.items():
            if "log4j" in dep.lower():
                # Conservative: any log4j 2.x not >=2.17 is flagged
                if re.match(r"2\.(\d+)", ver):
                    minor = int(re.match(r"2\.(\d+)", ver).group(1))
                    if minor < 17:
                        log4j_vulnerable = True

    for p in repo_root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not p.is_file() or SKIP.search(str(p)):
            continue
        lang = SUFFIX_TO_LANG.get(p.suffix.lower())
        if not lang:
            continue
        if languages and lang not in languages:
            continue
        try:
            if lang == "python":
                root = parse_python_file(p)
            else:
                root = parse_with_tree_sitter(p, lang)
        except Exception:
            continue
        if root is None:
            continue
        files_scanned += 1
        try:
            _analyze_module(
                root, p, repo_root, repo_name, lang,
                log4j_vulnerable, findings,
            )
        except Exception:
            continue

    return {
        "summary": (
            f"format_string: {len(findings)} findings across "
            f"{files_scanned} files"
            + (" (log4j vulnerable version detected)"
               if log4j_vulnerable else "")
        ),
        "findings": [_to_dict(f) for f in findings],
    }


def _analyze_module(
    root: Node, path: Path, repo_root: Path, repo_name: str, lang: str,
    log4j_vulnerable: bool, out: list[Finding],
) -> None:
    rel = str(path.relative_to(repo_root))
    for call in root.of_kind("Call"):
        callee = call.name or ""
        args = call.attrs.get("args", []) or []
        if not args:
            continue

        # printf-family check: first arg is the format string
        if PRINTF_RE.search(callee):
            fmt_arg = args[0]
            if not LITERAL_STR_RE.match(fmt_arg.strip()):
                # The format string is non-literal — CWE-134
                out.append(Finding(
                    kind="fmt_string",
                    repo=repo_name, file=rel, line=call.line,
                    function_qual=None,
                    cwe="CWE-134",
                    detail_md=(
                        f"`{callee}(...)` at {rel}:{call.line} — format "
                        f"argument is not a literal: `{fmt_arg[:120]}`. "
                        f"If this expression contains attacker-controlled "
                        f"data, `%n` allows arbitrary memory write; `%s` "
                        f"with bogus pointer causes crash."
                    ),
                    evidence={
                        "call": callee,
                        "format_arg": fmt_arg[:200],
                        "language": lang,
                    },
                    confidence=0.7,
                ))
            continue

        # Logger-as-template check
        is_java_logger = JAVA_LOGGER_RE.search(callee) and lang == "java"
        is_py_logger = PY_LOGGER_RE.search(callee) and lang == "python"

        if is_java_logger or is_py_logger:
            msg_arg = args[0]
            if not LITERAL_STR_RE.match(msg_arg.strip()):
                # Non-literal message → possible template injection
                # if the underlying impl interprets the message.
                conf = 0.8 if (is_java_logger and log4j_vulnerable) else 0.5
                cve_hint = (
                    "CVE-2021-44228 (log4shell)"
                    if (is_java_logger and log4j_vulnerable) else None
                )
                out.append(Finding(
                    kind="fmt_string",
                    repo=repo_name, file=rel, line=call.line,
                    function_qual=None,
                    cwe="CWE-117",
                    detail_md=(
                        f"`{callee}(...)` at {rel}:{call.line} logs a "
                        f"non-literal message. If the logger impl "
                        f"interprets format directives or template "
                        f"substitution syntax in the message, "
                        f"attacker-controlled input can trigger lookup "
                        f"expansion (e.g. ${{jndi:...}})."
                        + (f"\n\n**CVE hint:** {cve_hint}"
                           if cve_hint else "")
                    ),
                    evidence={
                        "call": callee,
                        "message_arg": msg_arg[:200],
                        "language": lang,
                        "log4j_vulnerable_dep": log4j_vulnerable,
                    },
                    confidence=conf,
                ))


def _to_dict(f: Finding) -> dict:
    return {
        "kind": f.kind, "repo": f.repo, "file": f.file, "line": f.line,
        "function_qual": f.function_qual, "cwe": f.cwe,
        "detail_md": f.detail_md, "evidence": f.evidence,
        "confidence": f.confidence,
    }
