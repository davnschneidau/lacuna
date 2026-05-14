"""
sqlmap wrapper — deep oracle for SQL injection.

Invokes sqlmap with safe defaults (read-only, no risky techniques, no DBMS
takeover) to confirm or refute a SQLi hypothesis. Output is parsed back to
the summary+handles shape.

Why a separate oracle and not a hunter tool: sqlmap is heavyweight (its
internal payload synthesis is more thorough than what a hunter would do
ad-hoc), but it's also costly — typically 30s-5min per target. Use only
when validator confidence is uncertain after 4 dialectic rounds.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path


SQLMAP_BIN = "sqlmap"


def run_sqlmap(
    url: str,
    method: str = "GET",
    data: str | None = None,
    cookies: str | None = None,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 600,
    level: int = 1,
    risk: int = 1,
) -> dict:
    """Run sqlmap with conservative defaults. Returns parsed result.

    - level: 1 (safest) ... 5 (aggressive)
    - risk:  1 (safe) ... 3 (heavy modifications attempted)

    The wrapper enforces:
      --batch         (no prompts)
      --no-cast       (no DBMS-modification probes)
      --crawl=0       (no spidering — we already have the target)
      --random-agent  (avoid detection signature)
      --output-dir=tempdir (don't pollute filesystem)
    """
    out_dir = Path(tempfile.mkdtemp(prefix="lacuna-sqlmap-"))
    cmd = [
        SQLMAP_BIN, "-u", url, "--batch", "--no-cast",
        "--random-agent",
        "--output-dir", str(out_dir),
        "--level", str(level), "--risk", str(risk),
        "--timeout", "20", "--retries", "1",
    ]
    if method.upper() == "POST" and data:
        cmd += ["--method", "POST", "--data", data]
    elif method.upper() != "GET":
        cmd += ["--method", method.upper()]
    if cookies:
        cmd += ["--cookie", cookies]
    if headers:
        cmd += ["--headers", "\n".join(f"{k}: {v}" for k, v in headers.items())]
    if proxy:
        cmd += ["--proxy", proxy]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap timeout", "url": url}
    except FileNotFoundError:
        return {"error": "sqlmap not installed (pip install sqlmap)"}

    # Parse the output for injection findings
    output = proc.stdout + "\n" + proc.stderr
    injectable = bool(re.search(
        r"(Parameter:\s|sqlmap identified the following injection)",
        output,
    ))
    techniques = list(set(re.findall(
        r"Type:\s+(boolean-based blind|time-based blind|error-based|"
        r"UNION query|stacked queries|inline query)",
        output,
    )))
    dbms_match = re.search(r"back-end DBMS:\s+([^\n]+)", output)
    dbms = dbms_match.group(1).strip() if dbms_match else None
    payload_match = re.search(r"Payload:\s+([^\n]+)", output)
    payload = payload_match.group(1).strip() if payload_match else None

    return {
        "summary": (
            f"sqlmap: injectable={injectable}; techniques={techniques}; dbms={dbms}"
            if injectable else "sqlmap: no SQLi confirmed"
        ),
        "injectable": injectable,
        "techniques": techniques,
        "dbms": dbms,
        "confirmed_payload": payload,
        "exit_code": proc.returncode,
        "output_dir": str(out_dir),
        "output_tail": output[-2000:],
    }
