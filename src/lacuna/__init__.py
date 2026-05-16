"""Lacuna — agentic application-level security scanner.

The version declared here is the single source of truth. Every other
artifact that needs a version string MUST read from this constant:

- ``pyproject.toml`` uses ``dynamic = ["version"]`` and reads this file.
- The CLI (``lacuna version``) imports ``__version__``.
- The report generator templates the header from ``__version__``.
- The SARIF emitter writes the driver version from ``__version__``.
- The DAST server's User-Agent string interpolates ``__version__``.
- The Playwright runner's UA string does the same.
- The Bitbucket pipe's pipe.sh shells out to read this value.
- The release CI verifies image tags match this string.

Version policy: bump the patch component for reconciliations (e.g. 3.1.1
to mark "all version strings now agree"); bump the minor for new
capabilities; bump the major for breaking changes to the manifest schema,
KG schema, or report layout. ``scripts/lint_versions.py`` enforces that
no other file hard-codes a literal that disagrees.
"""

__version__ = "3.1.1"

