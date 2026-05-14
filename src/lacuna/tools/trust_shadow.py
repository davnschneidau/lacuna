"""
Trust-shadow analyzer.

Builds the capability graph for an application:
  - For each repo, what secrets / keys / IAM roles / tokens does it hold?
  - What can each one DO (sign, decrypt, authorize, read)?
  - Which other repos TRUST that capability (verify sigs, accept tokens)?

The output goes into the KG `capabilities` + `capability_edges` tables.
Hunters can then ask: "which low-priv service holds a credential the
high-priv service trusts?" — a question that crosses repo boundaries and
isn't a finding in either repo alone.

This is run by a dedicated trust-shadow-analyzer agent (Opus tier) given
the call graph + secret_scan + cross_repo_calls outputs.
"""
from __future__ import annotations

import re
from pathlib import Path

# Patterns for finding signing operations, verification operations,
# and credential definitions
SIGN_PATTERNS = re.compile(
    r"jwt\.(encode|sign)|"
    r"hmac\.new|HMAC\.new|"
    r"Signer\.sign|"
    r"private_key\.sign|"
    r"signMessage|"
    r"\.create_token"
)
VERIFY_PATTERNS = re.compile(
    r"jwt\.(decode|verify)|"
    r"hmac\.compare_digest|"
    r"verify_signature|public_key\.verify|"
    r"\.validate_token"
)
SECRET_DEFINITION_PATTERNS = re.compile(
    r"""(\w*(?:SECRET|KEY|TOKEN|PASSWORD|CRED|PRIVATE_KEY)\w*)\s*[=:]\s*"""
    r"""['"][^'"]{8,}['"]|"""
    r"""os\.environ(?:\.get)?\(['"]?(\w*(?:SECRET|KEY|TOKEN|PASSWORD|CRED)\w*)"""
)
IAM_ROLE_PATTERNS = re.compile(
    r"""iam_role|AssumeRole|sts\.assume_role|"""
    r"""ServiceAccount|RoleArn""",
)


SKIP = re.compile(
    r"/(\.git|node_modules|\.venv|venv|__pycache__|dist|build|target|"
    r"vendor)/"
)


def analyze_repo(repo_root: Path, repo_name: str) -> dict:
    """Find capabilities + edges in a single repo.

    Returns a dict with two lists:
      capabilities: things this repo HOLDS (assets + what they grant)
      edges:        things this repo TRUSTS (relationships to assets)
    """
    capabilities: list[dict] = []
    edges: list[dict] = []
    suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb",
                ".cs", ".php"}

    for p in repo_root.rglob("*"):
        if not p.is_file() or SKIP.search(str(p)):
            continue
        if p.suffix.lower() not in suffixes \
                and p.name not in {"Dockerfile", ".env", ".env.example"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue

        # Capability discovery: secret definitions
        for m in SECRET_DEFINITION_PATTERNS.finditer(text):
            name = m.group(1) or m.group(2)
            if not name:
                continue
            asset_kind = _classify_asset(name)
            capabilities.append({
                "asset_kind": asset_kind,
                "asset_name": name,
                "holder_repo": repo_name,
                "file": str(p.relative_to(repo_root)),
                "line": text.count("\n", 0, m.start()) + 1,
            })

        # Edge: signs (this repo uses this capability to issue tokens)
        for m in SIGN_PATTERNS.finditer(text):
            # Find a nearby key reference
            window = text[max(0, m.start() - 200):m.end() + 100]
            keyref = re.search(r"\b(\w*(?:KEY|SECRET|TOKEN)\w*)\b", window)
            if keyref:
                edges.append({
                    "from_repo": repo_name,
                    "to_capability_hint": keyref.group(1),
                    "relationship": "signs_with",
                    "file": str(p.relative_to(repo_root)),
                    "line": text.count("\n", 0, m.start()) + 1,
                })

        # Edge: verifies (this repo trusts capabilities)
        for m in VERIFY_PATTERNS.finditer(text):
            window = text[max(0, m.start() - 200):m.end() + 100]
            keyref = re.search(r"\b(\w*(?:KEY|SECRET|TOKEN|PUB|JWKS)\w*)\b",
                                 window)
            if keyref:
                edges.append({
                    "from_repo": repo_name,
                    "to_capability_hint": keyref.group(1),
                    "relationship": "trusts",
                    "file": str(p.relative_to(repo_root)),
                    "line": text.count("\n", 0, m.start()) + 1,
                })

    return {
        "summary": (
            f"{repo_name}: {len(capabilities)} capabilities held, "
            f"{len(edges)} trust edges"
        ),
        "capabilities": capabilities,
        "edges": edges,
    }


def _classify_asset(name: str) -> str:
    upper = name.upper()
    if "PRIVATE_KEY" in upper or "RSA" in upper:
        return "private_key"
    if "PUBLIC_KEY" in upper or "PUB" in upper or "JWKS" in upper:
        return "public_key"
    if "JWT" in upper or "TOKEN_SIGNING" in upper or "HMAC" in upper:
        return "token_signing_key"
    if "PASSWORD" in upper or "PASSWD" in upper:
        return "password"
    if "API_KEY" in upper or "APIKEY" in upper:
        return "api_key"
    if "ROLE" in upper or "ARN" in upper:
        return "iam_role"
    if "SESSION" in upper:
        return "session_secret"
    return "secret"


def analyze_application(
    repos: dict[str, Path],
) -> dict:
    """Run trust-shadow analysis across multiple repos and emit a unified
    capability graph by matching asset names across repos.
    """
    per_repo: dict[str, dict] = {}
    for name, root in repos.items():
        per_repo[name] = analyze_repo(root, name)

    # Index capabilities by name for cross-repo edge resolution
    cap_by_name: dict[str, list[dict]] = {}
    for _repo_name, rep in per_repo.items():
        for cap in rep["capabilities"]:
            cap_by_name.setdefault(cap["asset_name"], []).append(cap)

    resolved_edges: list[dict] = []
    unresolved_hints: list[dict] = []
    for _repo_name, rep in per_repo.items():
        for edge in rep["edges"]:
            hint = edge["to_capability_hint"]
            matches = cap_by_name.get(hint, [])
            if matches:
                for cap in matches:
                    resolved_edges.append({
                        "from_repo": edge["from_repo"],
                        "to_holder_repo": cap["holder_repo"],
                        "to_asset_name": cap["asset_name"],
                        "to_asset_kind": cap["asset_kind"],
                        "relationship": edge["relationship"],
                        "via_file": edge["file"],
                        "via_line": edge["line"],
                    })
            else:
                unresolved_hints.append({**edge})

    # Compute interesting cross-repo trust patterns
    cross_repo_trust_paths = []
    for e in resolved_edges:
        if e["from_repo"] != e["to_holder_repo"] \
                and e["relationship"] in ("trusts", "signs_with"):
            cross_repo_trust_paths.append({
                "from": e["from_repo"], "to": e["to_holder_repo"],
                "asset": e["to_asset_name"], "rel": e["relationship"],
            })

    return {
        "summary": (
            f"capability graph: {sum(len(r['capabilities']) for r in per_repo.values())} "
            f"capabilities across {len(repos)} repos; "
            f"{len(resolved_edges)} resolved edges, "
            f"{len(cross_repo_trust_paths)} cross-repo trust paths"
        ),
        "per_repo": per_repo,
        "resolved_edges": resolved_edges,
        "unresolved_hints": unresolved_hints[:50],
        "cross_repo_trust_paths": cross_repo_trust_paths,
    }
