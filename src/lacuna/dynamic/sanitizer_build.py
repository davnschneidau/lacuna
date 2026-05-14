"""
Sanitizer build harness.

Auto-detects the project's build system, attempts a sanitizer-instrumented
build (ASan + UBSan by default), and returns:
  - Build status (success/failed/timeout)
  - Path to built binaries (for downstream fuzzer)
  - Sanitizer warnings extracted from the build log itself (UBSan flags
    signed-overflow / null-deref at compile time for many cases)

This is precondition infrastructure for `fuzzer.fuzz_function`. The build
is expensive (1-30 min); results are memoized in the KG.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BuildResult:
    repo_root: str
    sanitizers: str
    build_system: str | None
    status: str                                # success|failed|timeout|skipped
    command: str
    duration_s: int
    binaries: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    build_log_path: str | None = None
    error_message: str | None = None


# Default sanitizer combinations per language.
# ASan + UBSan is the standard for C/C++.
# Rust uses its own (`-Z sanitizer=address` with nightly).
# Go has a race detector.
DEFAULT_SANITIZERS = "asan,ubsan"


def detect_build_system(repo_root: Path) -> str | None:
    """Identify the build system by marker files."""
    markers = [
        ("cmake", "CMakeLists.txt"),
        ("autotools", "configure"),
        ("autotools", "configure.ac"),
        ("make", "Makefile"),
        ("make", "GNUmakefile"),
        ("cargo", "Cargo.toml"),
        ("go_mod", "go.mod"),
        ("npm", "package.json"),
        ("gradle", "build.gradle"),
        ("gradle", "build.gradle.kts"),
        ("maven", "pom.xml"),
        ("meson", "meson.build"),
        ("bazel", "WORKSPACE"),
        ("bazel", "BUILD"),
        ("bazel", "BUILD.bazel"),
    ]
    for system, marker in markers:
        if (repo_root / marker).exists():
            return system
    return None


def sanitizer_flags(sanitizers: str) -> dict[str, str]:
    """Return CFLAGS/CXXFLAGS/LDFLAGS additions for the chosen sanitizers."""
    flags: list[str] = []
    if "asan" in sanitizers:
        flags += ["-fsanitize=address", "-fno-omit-frame-pointer"]
    if "ubsan" in sanitizers:
        flags += ["-fsanitize=undefined"]
    if "msan" in sanitizers:
        flags += ["-fsanitize=memory", "-fno-omit-frame-pointer",
                  "-fsanitize-memory-track-origins=2"]
    if "fuzzer" in sanitizers:
        flags += ["-fsanitize=fuzzer-no-link"]
    flag_str = " ".join(flags)
    return {
        "CFLAGS":   flag_str,
        "CXXFLAGS": flag_str,
        "LDFLAGS":  flag_str,
        "CC":       "clang",
        "CXX":      "clang++",
    }


def build(
    repo_root: Path,
    sanitizers: str = DEFAULT_SANITIZERS,
    timeout_seconds: int = 1800,
    build_dir: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> BuildResult:
    """Detect build system and run a sanitizer-instrumented build."""
    start = time.time()
    bs = detect_build_system(repo_root)
    if bs is None:
        return BuildResult(
            repo_root=str(repo_root), sanitizers=sanitizers,
            build_system=None, status="skipped",
            command="", duration_s=0,
            error_message="no recognized build system",
        )

    # Skip systems where sanitizer build is not the standard idiom
    if bs in ("npm", "go_mod", "maven", "gradle"):
        return BuildResult(
            repo_root=str(repo_root), sanitizers=sanitizers,
            build_system=bs, status="skipped",
            command="", duration_s=0,
            error_message=f"{bs} doesn't use C-style sanitizers",
        )

    env = dict(os.environ)
    env.update(sanitizer_flags(sanitizers))
    if extra_env:
        env.update(extra_env)

    work = build_dir or (repo_root / "build-sanitizer")
    work.mkdir(parents=True, exist_ok=True)
    log_path = work / "build.log"

    # Per-system command sequence
    if bs == "cmake":
        cmds = [
            f"cmake -B {shlex.quote(str(work))} -S {shlex.quote(str(repo_root))} "
            f"-DCMAKE_BUILD_TYPE=Debug "
            f"-DCMAKE_C_FLAGS={shlex.quote(env['CFLAGS'])} "
            f"-DCMAKE_CXX_FLAGS={shlex.quote(env['CXXFLAGS'])}",
            f"cmake --build {shlex.quote(str(work))} -j",
        ]
    elif bs == "autotools":
        cmds = [
            (f"cd {shlex.quote(str(repo_root))} && "
             f"./configure CC=clang CXX=clang++ "
             f"CFLAGS={shlex.quote(env['CFLAGS'])} "
             f"CXXFLAGS={shlex.quote(env['CXXFLAGS'])}"),
            f"make -C {shlex.quote(str(repo_root))} -j",
        ]
    elif bs == "make":
        cmds = [f"make -C {shlex.quote(str(repo_root))} -j"]
    elif bs == "meson":
        cmds = [
            f"meson setup {shlex.quote(str(work))} {shlex.quote(str(repo_root))}",
            f"meson compile -C {shlex.quote(str(work))}",
        ]
    elif bs == "cargo":
        # Cargo with sanitizers — requires nightly
        cmds = [
            (f"cd {shlex.quote(str(repo_root))} && "
             f"RUSTFLAGS='-Z sanitizer=address' "
             f"cargo +nightly build --target x86_64-unknown-linux-gnu")
        ]
    else:
        return BuildResult(
            repo_root=str(repo_root), sanitizers=sanitizers,
            build_system=bs, status="skipped",
            command="", duration_s=0,
            error_message=f"unsupported build system: {bs}",
        )

    full_log = ""
    last_command = ""
    for cmd in cmds:
        last_command = cmd
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                env=env, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as e:
            full_log += f"\n=== TIMEOUT on: {cmd} ===\n{(e.stdout or '')}\n"
            log_path.write_text(full_log)
            return BuildResult(
                repo_root=str(repo_root), sanitizers=sanitizers,
                build_system=bs, status="timeout",
                command=last_command,
                duration_s=int(time.time() - start),
                build_log_path=str(log_path),
            )
        full_log += f"\n=== {cmd} ===\n{proc.stdout}\n{proc.stderr}\n"
        if proc.returncode != 0:
            log_path.write_text(full_log)
            return BuildResult(
                repo_root=str(repo_root), sanitizers=sanitizers,
                build_system=bs, status="failed",
                command=last_command,
                duration_s=int(time.time() - start),
                build_log_path=str(log_path),
                error_message=proc.stderr[-500:] if proc.stderr else None,
                warnings=parse_sanitizer_warnings(full_log),
            )

    log_path.write_text(full_log)

    binaries = _enumerate_binaries(work, repo_root)
    warnings = parse_sanitizer_warnings(full_log)

    return BuildResult(
        repo_root=str(repo_root), sanitizers=sanitizers,
        build_system=bs, status="success",
        command="; ".join(cmds),
        duration_s=int(time.time() - start),
        binaries=binaries,
        warnings=warnings,
        build_log_path=str(log_path),
    )


WARN_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+)(?::(?P<col>\d+))?:\s+"
    r"(?P<kind>warning|error|runtime error):\s*(?P<msg>.+)$",
    re.MULTILINE,
)


def parse_sanitizer_warnings(log_text: str) -> list[dict]:
    """Extract structured sanitizer warnings from build output."""
    warnings: list[dict] = []
    for m in WARN_RE.finditer(log_text):
        msg = m.group("msg").lower()
        # Classify
        kind = "compiler_warning"
        cwe = None
        if "signed integer overflow" in msg or "unsigned integer overflow" in msg:
            kind, cwe = "ubsan_integer_overflow", "CWE-190"
        elif "shift exponent" in msg:
            kind, cwe = "ubsan_shift", "CWE-682"
        elif "load of misaligned" in msg or "misaligned address" in msg:
            kind, cwe = "ubsan_misalign", "CWE-704"
        elif "null pointer" in msg:
            kind, cwe = "ubsan_null_deref", "CWE-476"
        elif "use after free" in msg or "heap-use-after-free" in msg:
            kind, cwe = "asan_uaf", "CWE-416"
        elif "heap-buffer-overflow" in msg or "stack-buffer-overflow" in msg:
            kind, cwe = "asan_bof", "CWE-787"
        else:
            continue
        warnings.append({
            "kind": kind, "cwe": cwe,
            "file": m.group("file"),
            "line": int(m.group("line")),
            "message": m.group("msg")[:200],
        })
    return warnings


def _enumerate_binaries(build_root: Path, repo_root: Path) -> list[dict]:
    """Find built artifacts: executables, shared libs, static libs."""
    bins: list[dict] = []
    if not build_root.exists():
        return bins
    for p in build_root.rglob("*"):
        if not p.is_file():
            continue
        # Executables (ELF/Mach-O are tricky to detect; use mode + name heuristic)
        mode = p.stat().st_mode
        is_executable = bool(mode & 0o111) and not p.suffix
        is_lib = p.suffix in {".so", ".dylib", ".a", ".dll"}
        if not (is_executable or is_lib):
            continue
        bins.append({
            "name": p.name,
            "path": str(p),
            "kind": "executable" if is_executable else "library",
            "size_bytes": p.stat().st_size,
        })
    return bins


def to_dict(r: BuildResult) -> dict:
    """Serialize a BuildResult for KG storage / MCP return."""
    return {
        "repo_root": r.repo_root,
        "sanitizers": r.sanitizers,
        "build_system": r.build_system,
        "status": r.status,
        "command": r.command,
        "duration_s": r.duration_s,
        "binaries": r.binaries,
        "warnings": r.warnings,
        "build_log_path": r.build_log_path,
        "error_message": r.error_message,
    }
