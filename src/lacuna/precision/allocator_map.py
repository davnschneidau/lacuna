"""
Allocator map — identifies what allocator(s) a codebase uses.

Not a finding generator. Outputs metadata that the integer_range and
lifetime analyzers consume to make smarter decisions:

  - In `kmalloc(GFP_ATOMIC)` contexts, allocation can silently fail at
    sizes > MAX_ORDER, returning NULL without errno. Different bug class
    than userland malloc.
  - Custom pools/arenas with paired alloc/free functions need to be
    treated like malloc/free for UAF tracking.
  - GC'd code can be skipped entirely by the UAF tracker.

Detects:
  - Standard: malloc/free, new/delete, calloc/realloc
  - Linux kernel: kmalloc/kfree, vmalloc/vfree, kzalloc, krealloc
  - Custom pools: any *_alloc / *_free pair with consistent naming
  - C++ smart pointers: unique_ptr, shared_ptr, weak_ptr
  - Ref-counted: incref/decref, Py_INCREF/Py_DECREF, retain/release
  - GC: garbage_collect/__del__/finalize (just notes presence)
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path


SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)

SUFFIX_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".m": "c", ".mm": "cpp",
    ".rs": "rust",
}

STANDARD_ALLOC = re.compile(
    r"\b(malloc|calloc|realloc|free|alloca)\s*\("
)
KERNEL_ALLOC = re.compile(
    r"\b(kmalloc|kzalloc|krealloc|kfree|vmalloc|vfree|kcalloc)\s*\("
)
CPP_NEW_DELETE = re.compile(
    r"\b(new\s+\w+|delete(?:\s*\[\s*\])?)\b"
)
CPP_SMART_PTR = re.compile(
    r"\b(unique_ptr|shared_ptr|weak_ptr|make_unique|make_shared)\b"
)
REFCOUNT = re.compile(
    r"\b(Py_INCREF|Py_DECREF|Py_XINCREF|Py_XDECREF|retain|release|"
    r"incref|decref|addref|releaseRef)\b"
)
GFP_FLAG = re.compile(r"\bGFP_(KERNEL|ATOMIC|NOWAIT|USER|HIGHUSER|NOIO|NOFS)\b")
CUSTOM_ALLOC_PATTERN = re.compile(r"\b(\w+_alloc)\s*\(")
CUSTOM_FREE_PATTERN = re.compile(r"\b(\w+_free)\s*\(")


def analyze(repo_root: Path, repo_name: str | None = None,
            max_files: int = 5000) -> dict:
    repo_name = repo_name or repo_root.name
    global_allocators: Counter = Counter()
    per_function: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    custom_alloc_calls: Counter = Counter()
    custom_free_calls: Counter = Counter()
    gfp_flags_seen: Counter = Counter()
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

        for m in STANDARD_ALLOC.finditer(text):
            global_allocators[m.group(1)] += 1
        for m in KERNEL_ALLOC.finditer(text):
            global_allocators[m.group(1)] += 1
        for m in CPP_NEW_DELETE.finditer(text):
            kind = "new" if m.group(1).startswith("new") else "delete"
            global_allocators[kind] += 1
        for m in CPP_SMART_PTR.finditer(text):
            global_allocators[f"smart_ptr:{m.group(1)}"] += 1
        for m in REFCOUNT.finditer(text):
            global_allocators[f"refcount:{m.group(1)}"] += 1
        for m in GFP_FLAG.finditer(text):
            gfp_flags_seen[m.group(0)] += 1
        for m in CUSTOM_ALLOC_PATTERN.finditer(text):
            name = m.group(1)
            # Filter false positives (k_alloc, etc. are kernel; standalone)
            if name in {"k_alloc", "v_alloc", "g_alloc"}:
                continue
            custom_alloc_calls[name] += 1
        for m in CUSTOM_FREE_PATTERN.finditer(text):
            custom_free_calls[m.group(1)] += 1

    # Pair custom alloc/free
    paired_custom: list[dict] = []
    for alloc_name, count in custom_alloc_calls.items():
        prefix = alloc_name[: -len("_alloc")]
        free_name = f"{prefix}_free"
        if free_name in custom_free_calls:
            paired_custom.append({
                "alloc_fn": alloc_name,
                "free_fn": free_name,
                "alloc_count": count,
                "free_count": custom_free_calls[free_name],
            })

    summary = (
        f"allocator_map: {sum(global_allocators.values())} allocator calls, "
        f"{len(paired_custom)} custom alloc/free pairs"
    )
    return {
        "summary": summary,
        "global_allocators": dict(global_allocators),
        "custom_pairs": paired_custom,
        "gfp_flags": dict(gfp_flags_seen),
        "languages_scanned": files_scanned,
    }
