"""
ffuf shadow surface discovery oracle.

Runs ffuf against a target base URL using the Lacuna shadow wordlist (or a
caller-supplied list). Returns discovered endpoints classified by HTTP status,
content-length, and title.

Design constraints:
  - Non-destructive: GET requests only, no mutation.
  - Rate-limited: max_rps enforced via ffuf's -rate flag.
  - Scope-checked: target must pass _allowed_host() before we run.
  - JSON output: parsed directly from ffuf's -json mode.
  - ffuf is optional: returns a graceful error dict if not in PATH.

Usage:
    result = run_ffuf(
        base_url="https://api.example.com",
        wordlist_path="/opt/lacuna/src/lacuna/data/shadow_wordlist.txt",
        allowed_host_patterns=["*.example.com"],
        max_rps=20,
        timeout_s=60,
    )
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_DEFAULT_WORDLIST = Path(__file__).parent.parent / "data" / "shadow_wordlist.txt"


def run_ffuf(
    base_url: str,
    allowed_host_patterns: list[str],
    wordlist_path: str | Path | None = None,
    max_rps: int = 20,
    timeout_s: int = 60,
    extra_headers: dict[str, str] | None = None,
    filter_status: list[int] | None = None,
    match_status: list[int] | None = None,
) -> dict:
    """
    Run ffuf for shadow surface discovery.

    Returns a dict with keys:
      discovered   — list of {url, status, length, words, lines, title}
      summary      — human-readable count string
      filtered_by  — which status codes were hidden (noise reduction)
      ffuf_version — version string from ffuf -V
      error        — set if ffuf is unavailable or the scan failed
    """
    host_err = _check_host(base_url, allowed_host_patterns)
    if host_err:
        return {"error": host_err}

    ffuf_path = _find_ffuf()
    if not ffuf_path:
        return {"error": "ffuf not found in PATH — install ffuf to enable shadow surface discovery"}

    wl = Path(wordlist_path) if wordlist_path else _DEFAULT_WORDLIST
    if not wl.exists():
        return {"error": f"wordlist not found: {wl}"}

    version = _get_version(ffuf_path)

    if filter_status is None:
        filter_status = [400, 404, 405, 501, 502, 503, 504]

    target = base_url.rstrip("/") + "/FUZZ"

    cmd = [
        ffuf_path,
        "-u", target,
        "-w", str(wl),
        "-of", "json",
        "-rate", str(max_rps),
        "-timeout", "10",
        "-maxtime", str(timeout_s),
        "-noninteractive",
        "-mc", "all",
    ]

    if filter_status:
        cmd += ["-fc", ",".join(str(c) for c in filter_status)]
    if match_status:
        cmd += ["-mc", ",".join(str(c) for c in match_status)]
    if extra_headers:
        for k, v in extra_headers.items():
            cmd += ["-H", f"{k}: {v}"]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        output_file = tf.name

    cmd += ["-o", output_file]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 10,
        )
    except subprocess.TimeoutExpired:
        _cleanup(output_file)
        return {"error": f"ffuf timed out after {timeout_s + 10}s"}
    except FileNotFoundError:
        _cleanup(output_file)
        return {"error": f"ffuf binary not executable: {ffuf_path}"}

    discovered: list[dict] = []
    try:
        raw = Path(output_file).read_text()
        if raw.strip():
            data = json.loads(raw)
            for r in (data.get("results") or []):
                discovered.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "redirectlocation": r.get("redirectlocation", ""),
                })
    except (json.JSONDecodeError, OSError):
        pass
    finally:
        _cleanup(output_file)

    by_status: dict[int, int] = {}
    for r in discovered:
        s = r["status"]
        by_status[s] = by_status.get(s, 0) + 1

    interesting = [r for r in discovered if r["status"] in (
        200, 201, 204, 301, 302, 307, 308, 401, 403
    )]

    return {
        "discovered": discovered,
        "interesting": interesting,
        "summary": (
            f"{len(discovered)} paths discovered, "
            f"{len(interesting)} interesting "
            f"(2xx/3xx/401/403)"
        ),
        "by_status": by_status,
        "filtered_by": filter_status,
        "target": target,
        "wordlist": str(wl),
        "ffuf_version": version,
        "stderr_tail": proc.stderr[-500:] if proc.stderr else "",
    }


def _check_host(url: str, allowed_patterns: list[str]) -> str | None:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
    except Exception:
        return f"cannot parse URL: {url}"
    if not allowed_patterns:
        return "no allowed_host_patterns configured — cannot run ffuf safely"
    for pat in allowed_patterns:
        if fnmatch.fnmatch(host, pat) or host == pat:
            return None
    return (
        f"host {host!r} does not match any allowed_host pattern "
        f"{allowed_patterns} — refusing to scan"
    )


def _find_ffuf() -> str | None:
    import shutil
    found = shutil.which("ffuf")
    if found:
        return found
    for candidate in ("/usr/local/bin/ffuf", "/usr/bin/ffuf", "/opt/ffuf/ffuf"):
        if Path(candidate).exists():
            return candidate
    return None


def _get_version(ffuf_path: str) -> str:
    try:
        r = subprocess.run([ffuf_path, "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout + r.stderr).strip()[:80]
    except Exception:
        return "unknown"


def _cleanup(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass
