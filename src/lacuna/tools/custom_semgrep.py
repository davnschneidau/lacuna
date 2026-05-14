"""
Custom Semgrep rule generator.

Given the framework footguns discovered by recon, generate a tailored semgrep
ruleset for THIS specific application's stack. Then run semgrep with that
ruleset instead of (or in addition to) the canned registry packs.

Why: canned semgrep packs are generic. They flag every `os.system` even when
your codebase has already wrapped it in a safe helper. A per-scan ruleset
can be much more precise — flag `os.system` ONLY in handlers, ONLY when the
argument isn't from `safe_cmd()`, etc.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

# Rule templates keyed by (framework, footgun).
# Each generator returns a list of semgrep rule dicts ready to dump as YAML.

def _rule_flask_render_template_string(repo_root: Path) -> list[dict]:
    return [{
        "id": "lacuna.flask.render-template-string-user-input",
        "message": (
            "render_template_string called with non-constant first arg. "
            "If the template body is user-controlled, this is SSTI → RCE."
        ),
        "severity": "ERROR",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "flask.render_template_string($X, ...)"},
            {"pattern": "render_template_string($X, ...)"},
        ],
        "pattern-not": {"pattern": 'render_template_string("...", ...)'},
        "metadata": {
            "category": "security", "cwe": ["CWE-94"],
            "footgun": "flask.render_template_string",
        },
    }]


def _rule_django_raw_sql(repo_root: Path) -> list[dict]:
    return [{
        "id": "lacuna.django.raw-sql-fstring",
        "message": (
            "Django ORM .raw() or .extra() with f-string SQL — parameterization "
            "is bypassed. Use parameterized .raw() with `params=[...]`."
        ),
        "severity": "ERROR",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "...objects.raw(f\"...\")"},
            {"pattern": "...objects.raw(f'...')"},
            {"pattern": "...objects.extra(where=[f\"...\"])"},
        ],
        "metadata": {"category": "security", "cwe": ["CWE-89"]},
    }]


def _rule_express_no_helmet(repo_root: Path) -> list[dict]:
    # Look for `const app = express()` without `app.use(helmet())`
    return [{
        "id": "lacuna.express.missing-helmet",
        "message": (
            "Express app does not appear to use the `helmet` middleware. "
            "Default headers (CSP, HSTS, etc.) will be missing."
        ),
        "severity": "WARNING",
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern": "const $APP = express(...)"},
            {"pattern-not-inside": "$APP.use(helmet(...))"},
        ],
        "metadata": {"category": "security", "cwe": ["CWE-693"]},
    }]


def _rule_jwt_alg_none(repo_root: Path) -> list[dict]:
    return [
        {
            "id": "lacuna.jwt.alg-none-accepted",
            "message": "jwt.decode accepts the 'none' algorithm — token forgery is trivial.",
            "severity": "ERROR",
            "languages": ["python"],
            "pattern-either": [
                {"pattern": 'jwt.decode($T, $K, algorithms=["none"])'},
                {"pattern": 'jwt.decode($T, $K, algorithms=["none", ...])'},
                {"pattern": 'jwt.decode($T, $K, verify=False)'},
            ],
            "metadata": {"category": "security", "cwe": ["CWE-347"]},
        },
        {
            "id": "lacuna.jwt.no-algorithm-pin",
            "message": "jwt.decode called without algorithms= pin. Algorithm confusion possible.",
            "severity": "WARNING",
            "languages": ["python"],
            "pattern": "jwt.decode($T, $K)",
            "metadata": {"category": "security", "cwe": ["CWE-347"]},
        },
    ]


def _rule_subprocess_shell_true(repo_root: Path) -> list[dict]:
    return [{
        "id": "lacuna.python.subprocess-shell-true",
        "message": (
            "subprocess.* call with shell=True. If any part of the command is "
            "user-controlled this is command injection."
        ),
        "severity": "ERROR",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "subprocess.run($CMD, ..., shell=True, ...)"},
            {"pattern": "subprocess.Popen($CMD, ..., shell=True, ...)"},
            {"pattern": "subprocess.call($CMD, ..., shell=True, ...)"},
            {"pattern": "subprocess.check_output($CMD, ..., shell=True, ...)"},
        ],
        "metadata": {"category": "security", "cwe": ["CWE-78"]},
    }]


def _rule_yaml_unsafe_load(repo_root: Path) -> list[dict]:
    return [{
        "id": "lacuna.python.yaml-unsafe-load",
        "message": (
            "yaml.load called without Loader=SafeLoader. Untrusted YAML can "
            "construct arbitrary Python objects → RCE."
        ),
        "severity": "ERROR",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "yaml.load($X)"},
            {"pattern": "yaml.load($X, Loader=yaml.Loader)"},
            {"pattern": "yaml.load($X, Loader=yaml.UnsafeLoader)"},
            {"pattern": "yaml.load($X, Loader=yaml.FullLoader)"},
        ],
        "metadata": {"category": "security", "cwe": ["CWE-502"]},
    }]


def _rule_pickle_load(repo_root: Path) -> list[dict]:
    return [{
        "id": "lacuna.python.pickle-load-untrusted",
        "message": (
            "pickle.load(s) on data that could be attacker-controlled is RCE."
        ),
        "severity": "ERROR",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "pickle.loads($X)"},
            {"pattern": "pickle.load($X)"},
            {"pattern": "cPickle.loads($X)"},
        ],
        "metadata": {"category": "security", "cwe": ["CWE-502"]},
    }]


# Framework → generator function map
FRAMEWORK_RULES = {
    "flask": _rule_flask_render_template_string,
    "django": _rule_django_raw_sql,
    "express": _rule_express_no_helmet,
}

# Language-level rules (run always for the language)
LANGUAGE_RULES = {
    "python": [
        _rule_subprocess_shell_true,
        _rule_yaml_unsafe_load,
        _rule_pickle_load,
        _rule_jwt_alg_none,
    ],
}


def build_ruleset(
    repo_root: Path, detected_frameworks: list[str],
    detected_languages: list[str],
) -> dict:
    """Build a tailored semgrep ruleset for this repo."""
    rules: list[dict] = []
    for fw in detected_frameworks:
        gen = FRAMEWORK_RULES.get(fw.lower())
        if gen:
            rules.extend(gen(repo_root))
    for lang in detected_languages:
        for gen in LANGUAGE_RULES.get(lang.lower(), []):
            rules.extend(gen(repo_root))
    return {"rules": rules}


def run_custom_semgrep(
    repo_root: Path, ruleset: dict, timeout: int = 300,
) -> dict:
    """Run semgrep with a custom ruleset. Returns matches in 'summary + handles' shape."""
    if not ruleset.get("rules"):
        return {
            "summary": "no custom rules generated for this repo",
            "handles": [],
        }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False,
    ) as f:
        yaml.safe_dump(ruleset, f)
        rules_path = f.name

    try:
        proc = subprocess.run(
            ["semgrep", "--config", rules_path, "--json", "--quiet",
             "--metrics", "off", "--timeout", "60", str(repo_root)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"error": f"semgrep failed: {e}"}

    if proc.returncode not in (0, 1):
        return {"error": f"semgrep error: {proc.stderr.strip()[:300]}"}
    try:
        report = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        report = {}
    results = report.get("results", []) or []
    handles = [{
        "rule": r.get("check_id"),
        "file": r.get("path"),
        "line": (r.get("start", {}) or {}).get("line"),
        "message": ((r.get("extra", {}) or {}).get("message") or "")[:200],
        "severity": (r.get("extra", {}) or {}).get("severity"),
    } for r in results]
    return {
        "summary": f"{len(handles)} hits from {len(ruleset['rules'])} custom rules",
        "rules_count": len(ruleset["rules"]),
        "handles": handles[:200],
    }
