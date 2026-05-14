"""
libFuzzer wrapper.

Given a function in a sanitizer-built artifact, generate a fuzzing harness,
build it, run libFuzzer for N seconds, and report:
  - Crashes (with ASan reports, stack traces, minimized inputs)
  - Coverage
  - Execution count

Harness generation supports the common C/C++ function signature shapes:
  int  func(const uint8_t *data, size_t size)   — already a libFuzzer-ready entry
  void func(const char *str)                    — null-terminated string
  void func(const uint8_t *data, size_t size)
  T    func(const T *struct_ptr, size_t size)

For exotic signatures, the wrapper falls back to a "best-effort" harness
that treats the first arg as buffer/length and ignores others. The
fuzzing-coordinator agent can refine.

Outputs go to {WORKSPACE}/fuzz/{repo}-{function_safe_name}/ with:
  harness.c        the generated entry point
  fuzz_target      the compiled binary
  corpus/          the seed corpus (initially empty)
  crashes/         libFuzzer-discovered inputs
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


HARNESS_TEMPLATES = {
    "bytes_size": '''
#include <stdint.h>
#include <stddef.h>

extern {return_type} {function_name}({param_decls});

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    {call_expr};
    return 0;
}}
''',
    "cstr": '''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern {return_type} {function_name}({param_decls});

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = 0;
    {call_expr};
    free(buf);
    return 0;
}}
''',
}


@dataclass
class FuzzResult:
    repo: str
    function: str
    binary_path: str
    harness_path: str
    target_path: str | None = None
    status: str = "unknown"           # completed|timeout|build_failed|crashed
    duration_s: int = 0
    executions: int | None = None
    executions_per_sec: int | None = None
    coverage_pct: float | None = None
    crashes: list[dict] = field(default_factory=list)
    error_message: str | None = None


def _safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)[:60]


def _classify_signature(signature: str) -> tuple[str, str, str]:
    """Classify a C/C++ function signature for harness selection.

    Returns (template_key, return_type, call_expr).
    """
    sig = signature.strip()
    # Strip outer parens
    m = re.match(
        r"^\s*(?P<ret>[\w\s\*]+?)\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*$",
        sig,
    )
    if not m:
        # Fallback: assume bytes/size
        return "bytes_size", "void", f"({signature})(Data, Size)"
    ret = m.group("ret").strip()
    name = m.group("name")
    args = [a.strip() for a in m.group("args").split(",") if a.strip()]

    # Detect known shapes
    if len(args) == 2 and \
            any(x in args[0] for x in ("uint8_t *", "char *", "u_char *",
                                          "const void *")) and \
            any(x in args[1] for x in ("size_t", "len", "size")):
        return "bytes_size", ret, f"{name}((const uint8_t *)Data, Size)"

    if len(args) == 1 and "char *" in args[0] and "const" in args[0]:
        return "cstr", ret, f"{name}(buf)"

    if len(args) == 1 and "uint8_t" in args[0]:
        return "bytes_size", ret, f"{name}((const uint8_t *)Data)"

    # Last-resort fallback
    return "bytes_size", ret, f"{name}((const uint8_t *)Data, Size)"


def generate_harness(
    function_name: str, signature: str, target_dir: Path,
) -> Path:
    """Write a libFuzzer harness file. Returns its path."""
    template_key, return_type, call_expr = _classify_signature(signature)
    # Re-derive param_decls
    m = re.match(
        r"^\s*[\w\s\*]+?\s+\w+\s*\((?P<args>[^)]*)\)\s*$", signature.strip(),
    )
    param_decls = m.group("args") if m else "const uint8_t *Data, size_t Size"

    harness = HARNESS_TEMPLATES[template_key].format(
        function_name=function_name,
        return_type=return_type or "void",
        param_decls=param_decls,
        call_expr=call_expr,
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    harness_path = target_dir / "harness.cc"
    harness_path.write_text(harness)
    return harness_path


def _build_target(
    harness_path: Path, library_path: str | Path, target_path: Path,
    extra_cflags: str = "",
    cxx_compiler: str = "clang++",
) -> tuple[bool, str]:
    """Compile the harness against the (sanitizer-built) library.
    Returns (success, log)."""
    cmd = (
        f"{cxx_compiler} -g -O1 "
        f"-fsanitize=address,fuzzer,undefined "
        f"-fno-omit-frame-pointer "
        f"{extra_cflags} "
        f"{shlex.quote(str(harness_path))} "
        f"{shlex.quote(str(library_path))} "
        f"-o {shlex.quote(str(target_path))} "
        f"-ldl -lpthread"
    )
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return False, "compilation timeout"
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


CRASH_DIR_RE = re.compile(r"^crash-[0-9a-f]+$")
ASAN_KIND_RE = re.compile(
    r"==\d+==ERROR:\s+AddressSanitizer:\s+(\S+)|"
    r"==\d+==ERROR:\s+UndefinedBehaviorSanitizer:\s+(\S+)|"
    r"runtime error:\s+(.+?)\n"
)
STACK_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(\S+):(\d+)",
    re.MULTILINE,
)


def fuzz_function(
    repo: str, function_name: str, signature: str,
    library_path: str | Path,
    timeout_seconds: int = 300,
    workspace: Path | None = None,
    seed_corpus: Path | None = None,
    max_total_runs: int | None = None,
) -> FuzzResult:
    """Generate a harness, build it, and run libFuzzer.

    library_path: path to the sanitizer-built static or shared library
    that contains `function_name`.
    """
    workspace = workspace or Path(
        os.environ.get("LACUNA_WORKSPACE", "/state/fuzz"),
    )
    target_dir = workspace / f"{_safe_name(repo)}-{_safe_name(function_name)}"
    target_dir.mkdir(parents=True, exist_ok=True)

    harness_path = generate_harness(function_name, signature, target_dir)
    target_bin = target_dir / "fuzz_target"
    ok, build_log = _build_target(harness_path, library_path, target_bin)

    result = FuzzResult(
        repo=repo, function=function_name,
        binary_path=str(library_path),
        harness_path=str(harness_path),
        target_path=str(target_bin) if ok else None,
    )

    if not ok:
        result.status = "build_failed"
        result.error_message = build_log[:2000]
        (target_dir / "build.log").write_text(build_log)
        return result

    corpus_dir = target_dir / "corpus"
    corpus_dir.mkdir(exist_ok=True)
    if seed_corpus and seed_corpus.exists():
        for s in seed_corpus.iterdir():
            if s.is_file():
                shutil.copy2(s, corpus_dir / s.name)

    crash_dir = target_dir / "crashes"
    crash_dir.mkdir(exist_ok=True)

    runs_arg = f"-runs={max_total_runs}" if max_total_runs else ""
    cmd = (
        f"{shlex.quote(str(target_bin))} "
        f"-max_total_time={timeout_seconds} "
        f"-print_final_stats=1 "
        f"-artifact_prefix={shlex.quote(str(crash_dir))}/ "
        f"{runs_arg} "
        f"{shlex.quote(str(corpus_dir))}"
    )

    start = time.time()
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout_seconds + 60,
        )
        log = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as e:
        log = (e.stdout or "") + (e.stderr or "")
        proc = None  # type: ignore

    result.duration_s = int(time.time() - start)

    # Parse run statistics
    m = re.search(r"stat::number_of_executed_units:\s+(\d+)", log)
    if m:
        result.executions = int(m.group(1))
    m = re.search(r"stat::average_exec_per_sec:\s+(\d+)", log)
    if m:
        result.executions_per_sec = int(m.group(1))
    m = re.search(r"#\d+\s+pulse\s+cov:\s+(\d+)", log)
    if m:
        # rough — coverage_pct is harder; we expose total feature count
        result.coverage_pct = None  # libFuzzer doesn't directly give %

    # Collect crashes from artifact_prefix dir
    crashes_found = sorted(crash_dir.glob("crash-*"))
    for c in crashes_found:
        # Re-run target on the crash to get the ASan report
        asan_log = _replay_crash(target_bin, c)
        asan_kind, stack = _parse_asan_report(asan_log)
        # Minimize
        min_path = _minimize_crash(target_bin, c, target_dir)
        # Save the ASan log alongside
        asan_log_path = target_dir / f"{c.name}.asan.log"
        asan_log_path.write_text(asan_log)
        result.crashes.append({
            "input_path": str(c),
            "minimized_input_path": str(min_path) if min_path else None,
            "asan_kind": asan_kind,
            "crash_stack": stack,
            "asan_log_path": str(asan_log_path),
        })

    result.status = (
        "crashed" if result.crashes
        else "completed" if proc and proc.returncode == 0
        else "timeout"
    )
    (target_dir / "fuzz.log").write_text(log[-200000:])
    return result


def _replay_crash(target: Path, input_path: Path) -> str:
    try:
        p = subprocess.run(
            [str(target), str(input_path)],
            capture_output=True, text=True, timeout=30,
        )
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + (e.stderr or "")
    except Exception as e:
        return f"replay failed: {e}"


def _parse_asan_report(log: str) -> tuple[str | None, list[str]]:
    m = ASAN_KIND_RE.search(log)
    kind = None
    if m:
        kind = (m.group(1) or m.group(2) or m.group(3) or "").strip()
    frames = []
    for m in STACK_FRAME_RE.finditer(log):
        frames.append(f"{m.group(1)} ({m.group(2)}:{m.group(3)})")
        if len(frames) >= 10:
            break
    return kind, frames


def _minimize_crash(target: Path, crash: Path, work_dir: Path) -> Path | None:
    """Run libFuzzer with -minimize_crash=1 to shrink the crash input."""
    min_path = work_dir / f"{crash.name}.min"
    cmd = [
        str(target),
        "-minimize_crash=1",
        "-runs=1000",
        f"-exact_artifact_path={min_path}",
        str(crash),
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
        return min_path if min_path.exists() else None
    except Exception:
        return None


def to_dict(r: FuzzResult) -> dict:
    return {
        "repo": r.repo, "function": r.function,
        "binary_path": r.binary_path, "harness_path": r.harness_path,
        "target_path": r.target_path,
        "status": r.status, "duration_s": r.duration_s,
        "executions": r.executions,
        "executions_per_sec": r.executions_per_sec,
        "coverage_pct": r.coverage_pct,
        "crashes": r.crashes,
        "error_message": r.error_message,
    }
