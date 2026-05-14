"""
Out-of-band callback collector client.

Lacuna doesn't ship its own OOB collector. The manifest must point at one —
options range from a public service to a self-hosted listener. The contract:

  POST {collector_url}/register
    body: { "label": "..." }
    → 201 { "token": "<random>", "callback_url": "https://<token>.<zone>/" }

  GET  {collector_url}/poll?token=<token>&since=<seconds>
    → 200 { "hits": [
              { "ts": "...", "proto": "dns"|"http", "src": "1.2.3.4", "path": "/x" },
              ...
            ]
         }

If your collector uses a different protocol, write an adapter in this file
and select it via the manifest's scan.dast.oob.protocol field.
"""
from __future__ import annotations

import secrets
from typing import Any

import httpx


class OobClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.collector_url = (cfg.get("collector_url") or "").rstrip("/")
        self.dns_zone = cfg.get("dns_zone", "oob.local")
        self.auth_header = cfg.get("auth_header")  # e.g. "Authorization: Bearer ..."
        self.timeout = float(cfg.get("timeout_s", 15))

    def _headers(self) -> dict:
        h: dict[str, str] = {}
        if self.auth_header:
            k, _, v = self.auth_header.partition(":")
            h[k.strip()] = v.strip()
        return h

    def register(self, label: str = "lacuna") -> tuple[str, str]:
        """Register a fresh OOB token. Returns (token, callback_url)."""
        if not self.collector_url:
            # Local-only token (no remote collector). Useful for offline tests.
            token = "lac" + secrets.token_hex(6)
            callback_url = f"https://{token}.{self.dns_zone}/"
            return token, callback_url
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.post(
                    f"{self.collector_url}/register",
                    json={"label": label},
                    headers=self._headers(),
                )
                r.raise_for_status()
                data = r.json()
                return data["token"], data["callback_url"]
        except Exception:
            # Fall back to local token; agent should treat poll() as best-effort
            token = "lac" + secrets.token_hex(6)
            callback_url = f"https://{token}.{self.dns_zone}/"
            return token, callback_url

    async def poll(self, token: str, since_seconds: int = 600) -> list[dict]:
        if not self.collector_url:
            return []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.get(
                    f"{self.collector_url}/poll",
                    params={"token": token, "since": since_seconds},
                    headers=self._headers(),
                )
                r.raise_for_status()
                return (r.json() or {}).get("hits", []) or []
        except Exception:
            return []
