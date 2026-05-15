"""
Lacuna tool-call result cache.

Caches deterministic, expensive recon tool results keyed on
(repo, git_sha, tool_name, args_hash). Persists to disk across scans when
/state/tool_cache/ is mounted as a volume.

Public API:
    get_cache()               -> DiskCache singleton
    cached(key_fn)            -> decorator for tool functions
    cache_key(repo, tool, **kw) -> str
"""
from __future__ import annotations

from .disk_cache import DiskCache, cache_key, cached, get_cache

__all__ = ["DiskCache", "cache_key", "cached", "get_cache"]
