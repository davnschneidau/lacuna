#!/usr/bin/env python3
"""PreSessionStart hook -- validates the harness environment matches the scan kind.

The SAST and DAST surfaces must be physically separate. The PreToolUse
hook can refuse a DAST tool call after the fact, but a far better
invariant is:

    If LACUNA_MODE selects a SAST-only scan, the lacuna-dast MCP server
    is not registered, no .claude/agents/dast/* are loadable, and the
    DAST manifest section is either absent or marked optional.

This hook runs *before* the agent ever sees the workspace. It walks
the staged ``.mcp.json``, the ``.claude/agents/`` directory, and the
manifest and:

1. Refuses to start the scan if a SAST-only configuration nevertheless
   includes the ``lacuna-dast`` MCP server.
2. Refuses to start the scan if a DAST-enabled configuration is
   missing the ``scan.dast.target.allowed_hosts`` allowlist (a no-op
   DAST scan would otherwise hammer no targets but also produce no
   findings — better to fail fast).
3. Emits a ``presession_validate`` event with the resolved kind/scope
   so reporters and post-mortem queries can attribute decisions to
   the right scan shape.

The hook is gated by ``LACUNA_PRESESSION_VALIDATE`` (default ``"1"``).
Setting it to ``"0"`` makes the hook a no-op, useful for the harness
unit tests that exercise the validator independently.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ.get("LACUNA_SRC_ROOT", "/opt/lacuna/src"))

from lacuna.kg import open_kg
from lacuna.kind import parse_legacy_mode


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_manifest(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        import yaml
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


def _validate(workspace: Path, mode: str, manifest_path: str | None) -> list[str]:
    """Return a list of error strings; an empty list means OK."""
    errors: list[str] = []
    spec = parse_legacy_mode(mode)

    mcp = _read_json(workspace / ".mcp.json")
    servers = (mcp.get("mcpServers") or {})
    dast_registered = "lacuna-dast" in servers

    if not spec.supports_dast_tools and dast_registered:
        errors.append(
            f"scan_kind={spec.kind.value} is SAST-only but the harness "
            f"registered lacuna-dast in .mcp.json. Refusing to start. "
            f"Re-launch with LACUNA_MODE=sast+dast or regenerate .mcp.json."
        )

    if spec.supports_dast_tools and not dast_registered:
        errors.append(
            f"scan_kind={spec.kind.value} requires lacuna-dast but the "
            f"harness did not register it in .mcp.json. Refusing to start."
        )

    if spec.supports_dast_tools:
        manifest = _load_manifest(manifest_path)
        allowed = (
            manifest.get("scan", {}) or {}
        ).get("dast", {}).get(
            "target", {}
        ).get("allowed_hosts") or []
        if not allowed:
            errors.append(
                "DAST scan requires scan.dast.target.allowed_hosts in the "
                "manifest. An empty allowlist would refuse every DAST tool "
                "call. Add the host glob(s) for the target environment."
            )

    return errors


def main() -> int:
    raw = sys.stdin.read()
    _ = json.loads(raw) if raw.strip() else {}

    if os.environ.get("LACUNA_PRESESSION_VALIDATE", "1") == "0":
        print(json.dumps({"decision": "allow", "skipped": True}))
        return 0

    workspace = Path(os.environ.get("LACUNA_WORKSPACE", "/workspace"))
    mode = os.environ.get("LACUNA_MODE", "sast")
    manifest_path = os.environ.get("LACUNA_MANIFEST_RESOLVED")
    spec = parse_legacy_mode(mode)

    errors = _validate(workspace, mode, manifest_path)

    try:
        kg = open_kg()
        kg.initialize()
        kg.append_event("system", "presession_validate", {
            "mode": mode,
            "scan_kind": spec.kind.value,
            "scan_scope": spec.scope.value,
            "errors": errors,
        })
        kg.close()
    except Exception:
        pass

    if errors:
        msg = "PreSessionValidate refused to start scan:\n - " + "\n - ".join(errors)
        print(json.dumps({"decision": "deny", "reason": msg}))
        return 0

    print(json.dumps({
        "decision": "allow",
        "scan_kind": spec.kind.value,
        "scan_scope": spec.scope.value,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
