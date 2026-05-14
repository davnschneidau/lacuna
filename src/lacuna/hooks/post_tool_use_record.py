#!/usr/bin/env python3
"""
PostToolUse hook — auto-records evidence and audits tool results.

For DAST tool calls especially, materializes the HTTP trace and OOB callback
data to /state/evidence/{tool_call_id}/ for later attachment to findings.

For all tools, records the call summary in the audit log.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg

# Restrictive whitelist: only ASCII alphanumerics, dashes, underscores. The
# previous code embedded ``tool_name`` directly into a filename, so a tool
# name like ``../../foo`` (which a malicious MCP server could declare)
# would escape the cache dir.
_TOOL_NAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_tool_name(name: str) -> str:
    cleaned = _TOOL_NAME_SAFE.sub("_", name or "")
    # Defence-in-depth: forbid leading dots so the result can't be a
    # hidden file, and cap length to keep filesystems happy.
    cleaned = cleaned.lstrip(".") or "tool"
    return cleaned[:64]


def _summarize_result(result: object) -> str:
    """Produce a ~200-char summary for audit. Full payload is on disk."""
    if isinstance(result, dict):
        keys = ", ".join(list(result.keys())[:8])
        return f"dict with keys: {keys}"
    if isinstance(result, list):
        return f"list[{len(result)}]"
    s = str(result)
    return s[:200] + ("…" if len(s) > 200 else "")


def main() -> int:
    raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}
    tool_name = hook_input.get("tool_name", "")
    tool_args = hook_input.get("tool_input", {}) or {}
    tool_result = hook_input.get("tool_result")
    agent = hook_input.get("agent", "unknown")

    evidence_dir = Path(os.environ.get("LACUNA_EVIDENCE_DIR", "/state/evidence"))
    cache_dir = Path(os.environ.get("LACUNA_TOOL_CACHE_DIR", "/state/tool_results"))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    payload_path: str | None = None
    safe_tool_name = _sanitize_tool_name(tool_name)
    if tool_result is not None:
        payload_bytes = json.dumps(tool_result, default=str).encode()
        h = hashlib.sha256(payload_bytes).hexdigest()[:16]
        payload_path = str(cache_dir / f"{safe_tool_name}-{h}.json")
        Path(payload_path).write_bytes(payload_bytes)

    kg = open_kg()
    try:
        kg.record_tool_call(
            agent=agent,
            tool=tool_name,
            args=tool_args if isinstance(tool_args, dict) else {"raw": str(tool_args)},
            result_summary=_summarize_result(tool_result),
            result_path=payload_path,
        )

        # Special handling: DAST HTTP requests get materialized as evidence-shaped
        # artifacts for easy attachment to findings later.
        if tool_name.startswith("lacuna-dast.http_request") and isinstance(tool_result, dict):
            ev_id = uuid.uuid4().hex[:12]
            ev_dir = evidence_dir / f"{safe_tool_name}-{ev_id}"
            ev_dir.mkdir(parents=True, exist_ok=True)
            (ev_dir / "request.json").write_text(
                json.dumps(tool_args, indent=2, default=str)
            )
            (ev_dir / "response.json").write_text(
                json.dumps(tool_result, indent=2, default=str)
            )
            kg.append_event(agent, "evidence_materialized", {
                "kind": "http_trace",
                "path": str(ev_dir),
            })
    finally:
        kg.close()

    print(json.dumps({"decision": "allow"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
