# Contributing to Lacuna

Thanks for considering a contribution. This document covers the practical
things - code style, tests, docs - but the more important thing first.

## What is wanted

- **Bug shapes Lacuna misses.** If you find a real vulnerability that
  Lacuna didn't surface, the diagnosis is more useful than the fix. Open
  an issue with the shape, the code that should have triggered a
  hypothesis, and the agent/hunter that should have caught it.

- **False positives.** A noisy scanner is worse than one with gaps.
  Refutations we should have made automatically are first-class issues.

- **New recon tools.** The recon MCP server is extensible — adding a
  framework-specific entrypoint detector or a new dependency-graph parser
  is usually 50 lines of Python and produces immediate value.

- **New hunter specializations.** A hunter for a vulnerability class we
  don't cover (e.g. AI/LLM injection, GraphQL-specific bugs).

- **DAST collector adapters.** The OOB client supports a generic
  register/poll protocol. If you have a different collector, an adapter
  is welcome.

## Development setup

```bash
git clone <fork>
cd lacuna
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

To test against a real scan, build the Docker image and run it against
`examples/app.lacuna.yaml` with a Foundry endpoint and a synthetic target.

## Tests

- `tests/test_kg.py` — knowledge graph invariants (dedup, exit criteria,
  finding-confirms-hypothesis).
- `tests/test_event_log.py` — durable event log behaviors.
- `tests/test_hooks.py` — hook stdin/stdout JSON contracts.

New code should come with a test. New tools (in any of the three MCP
servers) should have at minimum a test that the tool is listed and
returns a well-formed response shape.

## Style

- Python 3.11+.
- Ruff (`ruff check .`) — config in `pyproject.toml`.
- Type hints encouraged but not strictly required; `mypy --strict` is
  on the roadmap.
- Caveman style in *prompts and skills*, regular prose in code
  comments and docs.

## Pull request etiquette

- One conceptual change per PR.
- Include a paragraph in the description explaining *why* — the change
  isn't obvious from the diff.
- For new bug shapes / hunters / skills: include at least one synthetic
  example showing the shape, plus the hypothesis it should produce.

## Reporting security issues

Lacuna scans for security bugs. It will also have them. If you find a
security issue in Lacuna itself, please email security@your-org.example
rather than opening a public issue.
