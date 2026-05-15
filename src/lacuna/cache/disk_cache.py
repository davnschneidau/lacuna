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

import functools
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


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

    def invalidate(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def clear(self) -> int:
        """Delete all cache entries. Returns count deleted."""
        count = 0
        for p in self._root.glob("*.json"):
            p.unlink(missing_ok=True)
            count += 1
        return count

    def stats(self) -> dict:
        entries = list(self._root.glob("*.json"))
        total_bytes = sum(p.stat().st_size for p in entries if p.exists())
        return {
            "entries": len(entries),
            "size_mb": round(total_bytes / 1024 ** 2, 1),
            "cache_dir": str(self._root),
            "ttl_days": self._ttl_s / 86400,
        }

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


# ---------------------------------------------------------------------------
# Decorator

def cached(
    tool_name: str,
    key_fn: Callable[..., tuple[str, str, dict]] | None = None,
) -> Callable:
    """
    Decorator that wraps a recon tool function with disk caching.

    The decorated function must accept ``repo_path`` as its first positional
    arg (a Path) and ``repo_name`` as a keyword arg.

    ``key_fn`` receives the same args as the function and must return
    (repo_name, repo_path, extra_kwargs) for key construction.

    Usage:
        @cached("dependency_graph")
        def _compute_dep_graph(repo_path: Path, repo_name: str) -> dict:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if os.environ.get("LACUNA_CACHE_DISABLED", "").lower() in ("1", "true", "yes"):
                return fn(*args, **kwargs)
            if key_fn is not None:
                repo_name, repo_path, extra = key_fn(*args, **kwargs)
            else:
                repo_path = args[0] if args else kwargs.get("repo_path", Path("."))
                repo_name = kwargs.get("repo_name", str(repo_path.name))
                extra = {k: v for k, v in kwargs.items()
                         if k not in ("repo_path", "repo_name")}

            sha = git_sha_for(Path(repo_path))
            key = cache_key(repo_name, tool_name, sha, **extra)
            c = get_cache()
            hit = c.get(key)
            if hit is not None:
                return hit
            result = fn(*args, **kwargs)
            c.put(key, result)
            return result

        return wrapper
    return decorator


def _warn(msg: str) -> None:
    sys.stderr.write(f"[cache] {msg}\n")
    sys.stderr.flush()
