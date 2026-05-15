"""
Library-version → known-attack mapper.

Given a dependency list (from dependency_graph or dependency_vulns),
maps each library + version to known CVEs and security advisories using a
bundled lightweight corpus (no network required).

The corpus contains high-signal entries: libraries with a history of critical
CVEs, common in web applications, and most likely to be present in scanned
repos. This is NOT a full NIST NVD mirror — it is a curated fast-lookup
table for the most impactful library vulnerabilities Lacuna is likely to encounter.

Usage:
    from lacuna.patches.cve_mapper import map_dependencies, lookup_library
    hits = map_dependencies(deps_list)
    # deps_list: [{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}]
"""
from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Curated CVE corpus
# Format: {ecosystem: {package_name: [(version_range, cve_id, severity, summary, attack_type)]}}
# Version range: "<X.Y.Z" | ">=A,<B" | "=X.Y.Z" | "*" (all versions)

_CORPUS: dict[str, dict[str, list[tuple]]] = {
    "npm": {
        "lodash": [
            ("<4.17.21", "CVE-2021-23337", "high",
             "Command injection via _.template", "command_injection"),
            ("<4.17.20", "CVE-2020-28500", "medium",
             "ReDoS via trim functions", "redos"),
            ("<4.17.19", "CVE-2020-8203", "high",
             "Prototype pollution via _.zipObjectDeep", "prototype_pollution"),
            ("<4.17.12", "CVE-2019-10744", "critical",
             "Prototype pollution via defaultsDeep", "prototype_pollution"),
        ],
        "axios": [
            ("<0.21.2", "CVE-2021-3749", "high",
             "ReDoS via header normalization", "redos"),
            ("<1.6.0", "CVE-2023-45857", "medium",
             "CSRF via cross-origin cookie leak", "csrf"),
        ],
        "jsonwebtoken": [
            ("<9.0.0", "CVE-2022-23529", "high",
             "Arbitrary file write via manipulated secretOrPublicKey", "arbitrary_write"),
            ("<8.5.1", "CVE-2022-23539", "medium",
             "Weak key length allowed for HS algorithms", "weak_crypto"),
        ],
        "express": [
            ("<4.17.3", "CVE-2022-24999", "high",
             "Open redirect via qs parsing", "open_redirect"),
        ],
        "multer": [
            ("<1.4.4-lts.1", "CVE-2022-24434", "critical",
             "Prototype pollution", "prototype_pollution"),
        ],
        "semver": [
            ("<7.5.2", "CVE-2022-25883", "high",
             "ReDoS via untrusted version string", "redos"),
        ],
        "qs": [
            ("<6.10.3", "CVE-2022-24999", "high",
             "Prototype pollution via parsing", "prototype_pollution"),
        ],
        "moment": [
            ("<2.29.4", "CVE-2022-31129", "high",
             "ReDoS via parseZone", "redos"),
            ("<2.29.2", "CVE-2022-24785", "high",
             "Path traversal via user-controlled locale", "path_traversal"),
        ],
        "node-fetch": [
            ("<2.6.7", "CVE-2022-0235", "high",
             "Exposure of sensitive information via redirect", "info_leak"),
        ],
        "ws": [
            ("<5.2.3", "CVE-2021-32640", "high",
             "ReDoS via HTTP upgrade header", "redos"),
        ],
        "minimist": [
            ("<1.2.6", "CVE-2021-44906", "critical",
             "Prototype pollution via constructor", "prototype_pollution"),
        ],
        "tar": [
            ("<4.4.18", "CVE-2021-37713", "high",
             "Path traversal via arbitrary file creation", "path_traversal"),
        ],
    },
    "pypi": {
        "pyyaml": [
            ("<5.4", "CVE-2020-14343", "critical",
             "Arbitrary code execution via yaml.load() without Loader", "rce"),
            ("<5.1", "CVE-2019-20477", "critical",
             "Arbitrary code execution via Python object deserialisation", "rce"),
        ],
        "pillow": [
            ("<9.0.1", "CVE-2022-22817", "critical",
             "Arbitrary code execution via PIL.ImageMath.eval", "rce"),
            ("<8.3.2", "CVE-2021-23437", "high",
             "Denial of service via large palette", "dos"),
        ],
        "cryptography": [
            ("<41.0.2", "CVE-2023-38325", "high",
             "NULL pointer deref in PKCS12 parsing", "dos"),
            ("<3.2.2", "CVE-2020-36242", "critical",
             "Buffer overflow via large backend passwords", "buffer_overflow"),
        ],
        "requests": [
            ("<2.31.0", "CVE-2023-32681", "medium",
             "Unintended leak of Proxy-Authorization header", "info_leak"),
        ],
        "django": [
            ("<4.2.1", "CVE-2023-31047", "critical",
             "File upload bypass via upload validation", "file_upload_bypass"),
            ("<3.2.18", "CVE-2023-24580", "high",
             "DoS via memory exhaustion in multipart requests", "dos"),
            ("<2.2.28", "CVE-2022-22818", "medium",
             "XSS via debug views", "xss"),
        ],
        "flask": [
            ("<2.3.2", "CVE-2023-30861", "high",
             "Session cookie leakage when using proxy", "info_leak"),
        ],
        "jinja2": [
            ("<3.1.3", "CVE-2024-22195", "medium",
             "XSS via xmlattr filter", "xss"),
            ("<2.11.3", "CVE-2020-28493", "high",
             "ReDoS via crafted template", "redos"),
        ],
        "paramiko": [
            ("<3.4.0", "CVE-2023-48795", "medium",
             "Terrapin attack (SSH prefix truncation)", "crypto"),
        ],
        "pyopenssl": [
            ("<23.2.0", "CVE-2023-49083", "medium",
             "NULL pointer deref in certificate chain handling", "dos"),
        ],
        "celery": [
            ("<5.2.2", "CVE-2021-23727", "high",
             "Task result stored in insecure backend", "info_leak"),
        ],
        "sqlalchemy": [
            ("<1.4.49", "CVE-2023-30608", "high",
             "SQL injection via bypass of coercions", "sqli"),
        ],
        "werkzeug": [
            ("<3.0.3", "CVE-2024-34069", "high",
             "Remote code execution via debugger PIN bypass", "rce"),
            ("<2.3.8", "CVE-2023-46136", "high",
             "DoS via multipart/form-data parsing", "dos"),
        ],
    },
    "maven": {
        "org.springframework:spring-webmvc": [
            ("<5.3.20", "CVE-2022-22965", "critical",
             "Spring4Shell — RCE via DataBinder", "rce"),
        ],
        "org.apache.logging.log4j:log4j-core": [
            ("<2.17.1", "CVE-2021-44228", "critical",
             "Log4Shell — JNDI injection RCE", "rce"),
            ("<2.17.1", "CVE-2021-45046", "critical",
             "Log4Shell bypass — JNDI injection", "rce"),
        ],
        "com.fasterxml.jackson.core:jackson-databind": [
            ("<2.14.1", "CVE-2022-42003", "high",
             "DoS via deeply nested objects", "dos"),
            ("<2.12.7", "CVE-2021-46877", "high",
             "DoS via HashMap key collisions", "dos"),
        ],
        "org.apache.struts:struts2-core": [
            ("<2.5.33", "CVE-2023-50164", "critical",
             "File upload path traversal → RCE", "rce"),
        ],
    },
    "go": {
        "github.com/golang-jwt/jwt": [
            ("<4.5.0", "CVE-2022-39227", "high",
             "Signing key confusion via None algorithm", "jwt_none_alg"),
        ],
    },
}


# ---------------------------------------------------------------------------
# Public API

def lookup_library(
    name: str, version: str, ecosystem: str
) -> list[dict]:
    """Return known CVEs for a library at a specific version."""
    eco = ecosystem.lower()
    pkg_map = _CORPUS.get(eco, {})
    entries = pkg_map.get(name.lower(), []) or pkg_map.get(name, [])
    results = []
    for ver_range, cve_id, severity, summary, attack_type in entries:
        if _version_in_range(version, ver_range):
            results.append({
                "cve": cve_id,
                "severity": severity,
                "summary": summary,
                "attack_type": attack_type,
                "affected_range": ver_range,
                "library": name,
                "version": version,
                "ecosystem": ecosystem,
            })
    return results


def map_dependencies(deps: list[dict]) -> list[dict]:
    """Map a list of dependency dicts to known CVEs.

    Each dep dict should have at minimum: name, version, ecosystem.
    Returns a list of CVE hit dicts sorted by severity.
    """
    hits: list[dict] = []
    for dep in deps:
        name = dep.get("name", "")
        version = dep.get("version", "") or ""
        ecosystem = dep.get("ecosystem", "")
        hits.extend(lookup_library(name, version, ecosystem))
    return sorted(hits, key=lambda h: _SEV_ORDER.get(h["severity"], 99))


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Version comparison (simple semver subset)

def _version_in_range(version: str, range_str: str) -> bool:
    """Check if version satisfies the range string.

    Supports: <X.Y.Z, >=A.B.C,<X.Y.Z, =X.Y.Z, *, and compound AND ranges.
    """
    version = version.strip().lstrip("v=~^")
    if not version or version in ("*", ""):
        return True
    if range_str == "*":
        return True

    try:
        ver = _parse_ver(version)
    except Exception:
        return False

    for part in range_str.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith(">="):
            if not (ver >= _parse_ver(part[2:])):
                return False
        elif part.startswith("<="):
            if not (ver <= _parse_ver(part[2:])):
                return False
        elif part.startswith("<"):
            if not (ver < _parse_ver(part[1:])):
                return False
        elif part.startswith(">"):
            if not (ver > _parse_ver(part[1:])):
                return False
        elif part.startswith("="):
            if ver != _parse_ver(part[1:]):
                return False
    return True


def _parse_ver(s: str) -> tuple[int, ...]:
    s = s.strip().lstrip("v=")
    s = re.split(r"[-+]", s)[0]
    parts = s.split(".")
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result)
