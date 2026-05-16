"""
Disk-based tool-call result cache for Lacuna recon tools.

Cache key: SHA-256(repo + git_sha + tool_name + sorted(args))
Storage:   /state/tool_cache/<key>.json  (JSON envelope + result)
TTL:       LACUNA_CACHE_TTL_DAYS (default 7)
Max size:  LACUNA_CACHE_MAX_GB (default 10)  — LRU eviction

Tools that are safe to cache (deterministic given same git_sha):
  dependency_graph, custom_semgrep_scan, call_graph_at,
  data_flow_paths, ast_query, taint_paths, language_stats,
  framework_detect, entrypoints (full-scan mode only),
  data_sinks, data_sources
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


_INSTANCE: DiskCache | None = None


def get_cache() -> DiskCache:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = DiskCache()
    return _INSTANCE


class DiskCache:
    """Persistent disk cache for deterministic recon tool results."""

    def __init__(self) -> None:
        cache_dir = os.environ.get("LACUNA_TOOL_CACHE_DIR", "/state/tool_cache")
        self._root = Path(cache_dir)
        self._root.mkdir(parents=True, exist_ok=True)

        raw_ttl = os.environ.get("LACUNA_CACHE_TTL_DAYS", "7")
        try:
            self._ttl_s = float(raw_ttl) * 86400
        except ValueError:
            self._ttl_s = 7 * 86400

        raw_max = os.environ.get("LACUNA_CACHE_MAX_GB", "10")
        try:
            self._max_bytes = int(float(raw_max) * 1024 ** 3)
        except ValueError:
            self._max_bytes = 10 * 1024 ** 3

    # ------------------------------------------------------------------
    # Public interface

    def get(self, key: str) -> Any | None:
        """Return cached result or None on miss/expiry."""
        p = self._path(key)
        if not p.exists():
            return None
        try:
            envelope = json.loads(p.read_bytes())
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - envelope.get("cached_at", 0) > self._ttl_s:
            p.unlink(missing_ok=True)
            return None
        return envelope.get("result")

    def put(self, key: str, result: Any) -> None:
        """Store a result. Triggers LRU eviction if over max size."""
        p = self._path(key)
        try:
            p.write_text(json.dumps({
                "key": key,
                "cached_at": time.time(),
                "result": result,
            }, default=str))
        except OSError as e:
            _warn(f"cache write failed for {key}: {e}")
            return
        self._maybe_evict()

    # ------------------------------------------------------------------
    # Private

    def _path(self, key: str) -> Path:
        return self._root / f"{key}.json"

    def _maybe_evict(self) -> None:
        entries = [(p, p.stat().st_size, p.stat().st_mtime)
                   for p in self._root.glob("*.json") if p.exists()]
        total = sum(s for _, s, _ in entries)
        if total <= self._max_bytes:
            return
        entries.sort(key=lambda x: x[2])
        for p, size, _ in entries:
            p.unlink(missing_ok=True)
            total -= size
            if total <= self._max_bytes * 0.8:
                break


# ---------------------------------------------------------------------------
# Key construction

def cache_key(repo: str, tool: str, git_sha: str, **kwargs: Any) -> str:
    """Build a stable cache key from repo, tool name, git SHA, and extra args."""
    parts = json.dumps(kwargs, sort_keys=True, default=str)
    raw = f"{repo}\x00{tool}\x00{git_sha}\x00{parts}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def git_sha_for(repo_path: Path) -> str:
    """Return the current HEAD SHA for a repo path, or 'unknown'."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_path),
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()[:40]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "unknown"


def _warn(msg: str) -> None:
    sys.stderr.write(f"[cache] {msg}\n")
    sys.stderr.flush()
