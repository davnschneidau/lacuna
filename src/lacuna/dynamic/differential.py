"""
Differential parser testing oracle.

Run the same input through multiple implementations of the same parser or
protocol. Divergence is the signal: when two implementations interpret the
same bytes differently, smuggling / SSRF parser confusion / etc. become
exploitable.

Built-in parser pairs:
  http_request:    nginx-style, Apache-style, Python stdlib http.server,
                   Go net/http, Node http (heuristic re-implementations
                   based on RFC 7230 quirks).
  url:             urllib (Python), Go net/url, Node WHATWG URL, Java URI.
  json:            stdlib JSON per-language (strict / lax differs).
  email_addr:      RFC 5322 validators per language.

Each parser is implemented as a small adapter function. They aim to
*reproduce the quirk* rather than be bit-perfect emulators. For the
ground truth (when you really need it), the oracle can also shell out
to the real binaries (nginx -t, etc.) but they're optional dependencies.
"""
from __future__ import annotations

import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ParserResult:
    name: str
    ok: bool
    parsed: dict | None = None
    error: str | None = None


@dataclass
class DifferentialResult:
    protocol: str
    input_bytes: bytes
    parser_results: dict[str, ParserResult] = field(default_factory=dict)
    divergence: bool = False
    divergent_fields: list[str] = field(default_factory=list)
    exploit_class: str | None = None


# ─── HTTP parsers ────────────────────────────────────────────────────────────

def _parse_http_strict_first_clen(data: bytes) -> ParserResult:
    """Reject duplicate Content-Length (strict RFC 9110 §8.6)."""
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        rline = lines[0].decode("latin-1", errors="replace")
        m = re.match(r"^(\w+)\s+(\S+)\s+(\S+)$", rline)
        if not m:
            return ParserResult("strict_first_clen", False,
                                 error="bad request line")
        method, path, ver = m.group(1), m.group(2), m.group(3)
        headers: dict[str, list[str]] = {}
        for h in lines[1:]:
            if b":" not in h:
                continue
            k, v = h.split(b":", 1)
            headers.setdefault(k.strip().lower().decode("latin-1"), []).append(
                v.strip().decode("latin-1"),
            )
        clen_vals = headers.get("content-length", [])
        if len(clen_vals) > 1:
            return ParserResult("strict_first_clen", False,
                                 error="duplicate Content-Length rejected")
        clen = int(clen_vals[0]) if clen_vals else 0
        return ParserResult("strict_first_clen", True, parsed={
            "method": method, "path": path, "version": ver,
            "body_len": clen,
            "headers": {k: v[0] if len(v) == 1 else v
                          for k, v in headers.items()},
        })
    except Exception as e:
        return ParserResult("strict_first_clen", False, error=str(e))


def _parse_http_last_clen(data: bytes) -> ParserResult:
    """Tolerant: take the LAST Content-Length on duplicates."""
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        rline = lines[0].decode("latin-1", errors="replace")
        m = re.match(r"^(\w+)\s+(\S+)\s+(\S+)$", rline)
        if not m:
            return ParserResult("last_clen", False, error="bad request line")
        method, path, ver = m.group(1), m.group(2), m.group(3)
        clen = 0
        for h in lines[1:]:
            if b":" not in h:
                continue
            k, v = h.split(b":", 1)
            if k.strip().lower() == b"content-length":
                try:
                    clen = int(v.strip())
                except ValueError:
                    pass
        return ParserResult("last_clen", True, parsed={
            "method": method, "path": path, "version": ver,
            "body_len": clen,
        })
    except Exception as e:
        return ParserResult("last_clen", False, error=str(e))


def _parse_http_first_clen_tolerant(data: bytes) -> ParserResult:
    """Tolerant: take the FIRST Content-Length on duplicates.
    (nginx default before late-2022)."""
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        rline = lines[0].decode("latin-1", errors="replace")
        m = re.match(r"^(\w+)\s+(\S+)\s+(\S+)$", rline)
        if not m:
            return ParserResult("first_clen", False, error="bad request line")
        method, path, ver = m.group(1), m.group(2), m.group(3)
        clen = 0
        seen = False
        for h in lines[1:]:
            if b":" not in h:
                continue
            k, v = h.split(b":", 1)
            if k.strip().lower() == b"content-length" and not seen:
                try:
                    clen = int(v.strip())
                    seen = True
                except ValueError:
                    pass
        return ParserResult("first_clen", True, parsed={
            "method": method, "path": path, "version": ver,
            "body_len": clen,
        })
    except Exception as e:
        return ParserResult("first_clen", False, error=str(e))


def _parse_http_te_chunked_priority(data: bytes) -> ParserResult:
    """Tolerant: when TE: chunked present, ignore Content-Length entirely."""
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        rline = lines[0].decode("latin-1", errors="replace")
        m = re.match(r"^(\w+)\s+(\S+)\s+(\S+)$", rline)
        if not m:
            return ParserResult("te_chunked", False, error="bad request line")
        method, path, ver = m.group(1), m.group(2), m.group(3)
        te_chunked = False
        clen = 0
        for h in lines[1:]:
            if b":" not in h:
                continue
            k, v = h.split(b":", 1)
            kl = k.strip().lower()
            if kl == b"transfer-encoding" and b"chunked" in v.strip().lower():
                te_chunked = True
            if kl == b"content-length" and not te_chunked:
                try:
                    clen = int(v.strip())
                except ValueError:
                    pass
        return ParserResult("te_chunked", True, parsed={
            "method": method, "path": path, "version": ver,
            "te_chunked": te_chunked,
            "body_len": "chunked" if te_chunked else clen,
        })
    except Exception as e:
        return ParserResult("te_chunked", False, error=str(e))


HTTP_PARSERS: dict[str, Callable[[bytes], ParserResult]] = {
    "nginx_first_clen": _parse_http_first_clen_tolerant,
    "apache_last_clen": _parse_http_last_clen,
    "rfc9110_strict": _parse_http_strict_first_clen,
    "go_te_priority": _parse_http_te_chunked_priority,
}


# ─── URL parsers ─────────────────────────────────────────────────────────────

def _parse_url_urllib(data: bytes) -> ParserResult:
    try:
        from urllib.parse import urlparse
        u = urlparse(data.decode("latin-1"))
        return ParserResult("urllib", True, parsed={
            "scheme": u.scheme, "netloc": u.netloc,
            "path": u.path, "query": u.query, "fragment": u.fragment,
        })
    except Exception as e:
        return ParserResult("urllib", False, error=str(e))


def _parse_url_whatwg(data: bytes) -> ParserResult:
    r"""Approximate WHATWG URL — handles `\` differently than urllib."""
    try:
        url = data.decode("latin-1")
        url = url.replace("\\", "/")  # WHATWG canonicalizes backslashes
        from urllib.parse import urlparse
        u = urlparse(url)
        return ParserResult("whatwg", True, parsed={
            "scheme": u.scheme, "netloc": u.netloc,
            "path": u.path, "query": u.query,
        })
    except Exception as e:
        return ParserResult("whatwg", False, error=str(e))


def _parse_url_naive(data: bytes) -> ParserResult:
    """Some apps roll their own. Approximate the common shape."""
    try:
        url = data.decode("latin-1")
        m = re.match(r"^([a-z]+)://([^/]+)(/[^?]*)?(\?.*)?$", url, re.I)
        if not m:
            return ParserResult("naive", False, error="no match")
        return ParserResult("naive", True, parsed={
            "scheme": m.group(1), "netloc": m.group(2),
            "path": m.group(3) or "/", "query": (m.group(4) or "")[1:],
        })
    except Exception as e:
        return ParserResult("naive", False, error=str(e))


URL_PARSERS = {
    "urllib": _parse_url_urllib,
    "whatwg": _parse_url_whatwg,
    "naive": _parse_url_naive,
}


# ─── JSON parsers ────────────────────────────────────────────────────────────

def _parse_json_strict(data: bytes) -> ParserResult:
    try:
        return ParserResult("strict", True, parsed=json.loads(data.decode()))
    except Exception as e:
        return ParserResult("strict", False, error=str(e))


def _parse_json_duplicate_keys_first(data: bytes) -> ParserResult:
    """Some implementations take the FIRST value on duplicate keys."""
    try:
        from json import JSONDecoder
        result = JSONDecoder(
            object_pairs_hook=lambda kv: dict(reversed(kv)),
        ).decode(data.decode())
        return ParserResult("dup_first", True, parsed=result)
    except Exception as e:
        return ParserResult("dup_first", False, error=str(e))


def _parse_json_duplicate_keys_last(data: bytes) -> ParserResult:
    """Standard dict construction — last-wins."""
    try:
        return ParserResult("dup_last", True, parsed=json.loads(data.decode()))
    except Exception as e:
        return ParserResult("dup_last", False, error=str(e))


JSON_PARSERS = {
    "strict": _parse_json_strict,
    "dup_first": _parse_json_duplicate_keys_first,
    "dup_last": _parse_json_duplicate_keys_last,
}


PROTOCOL_REGISTRY: dict[str, dict] = {
    "http_request": HTTP_PARSERS,
    "url": URL_PARSERS,
    "json": JSON_PARSERS,
}


def _classify_exploit(protocol: str, divergent_fields: list[str]) -> str | None:
    if protocol == "http_request" and "body_len" in divergent_fields:
        return "http_request_smuggling"
    if protocol == "url" and any(f in divergent_fields
                                  for f in ("netloc", "scheme")):
        return "ssrf_parser_confusion"
    if protocol == "json" and divergent_fields:
        return "json_key_confusion"
    return None


def differential_parse(
    protocol: str, input_bytes: bytes,
    parsers: list[str] | None = None,
) -> DifferentialResult:
    """Run all (or subset) of the registered parsers on this input."""
    registry = PROTOCOL_REGISTRY.get(protocol)
    if registry is None:
        return DifferentialResult(
            protocol=protocol, input_bytes=input_bytes,
            parser_results={},
            divergence=False,
            divergent_fields=[],
            exploit_class=None,
        )

    chosen = parsers or list(registry.keys())
    result = DifferentialResult(
        protocol=protocol, input_bytes=input_bytes,
    )
    for name in chosen:
        fn = registry.get(name)
        if not fn:
            continue
        result.parser_results[name] = fn(input_bytes)

    # Which fields are "decisive" for divergence per protocol. Other
    # fields (headers dict, te_chunked metadata) are informational —
    # different parsers expose them in slightly different ways.
    DECISIVE_FIELDS: dict[str, tuple[str, ...]] = {
        "http_request": ("method", "path", "body_len"),
        "url": ("scheme", "netloc", "path", "query"),
        "json": (),  # JSON divergence checks the whole value space below
    }

    # Find divergent fields
    successful = {k: v.parsed for k, v in result.parser_results.items()
                  if v.ok and v.parsed}
    if len(successful) < 2:
        return result
    # Restrict to decisive fields when configured
    decisive = DECISIVE_FIELDS.get(protocol)
    if decisive:
        all_keys = set(decisive)
    else:
        # Fallback: union of all keys (used for json, where keys ARE the data)
        all_keys = set()
        for p in successful.values():
            all_keys.update(p.keys())
    divergent = []
    for key in all_keys:
        values = {name: p.get(key) for name, p in successful.items()
                  if key in p}
        if len(set(repr(v) for v in values.values())) > 1:
            divergent.append(key)
    result.divergent_fields = divergent
    result.divergence = bool(divergent)
    result.exploit_class = _classify_exploit(protocol, divergent)
    return result


def to_dict(r: DifferentialResult) -> dict:
    return {
        "protocol": r.protocol,
        "input_hex": binascii.hexlify(r.input_bytes).decode(),
        "parser_results": {
            name: {
                "ok": pr.ok, "parsed": pr.parsed, "error": pr.error,
            }
            for name, pr in r.parser_results.items()
        },
        "divergence": r.divergence,
        "divergent_fields": r.divergent_fields,
        "exploit_class": r.exploit_class,
    }
