"""
Lacuna patch-diff and variant-search infrastructure.

The fix for a bug is evidence about the bug class. Most fix commits
address ONE manifestation; the variant space survives.

Modules:
  patch_essence:  given a git commit (or diff text), distill the bug-class
                  abstraction and generate a semgrep-style rule that
                  matches the BEFORE pattern.

  propagate:      given a generated rule, run it across the codebase to
                  find sibling sites that match the same pattern.

The combined workflow:
  1. `extract_essence(commit_sha)` -> rule
  2. `propagate_pattern(rule)` -> matches
  3. Each match becomes a hypothesis at confidence 0.6 with parent_finding_id

Without external CVE corpus, this works on the user's own git history.
The `patch-archaeologist` agent runs across `recent_security_commits`;
the `variant-hunter` agent runs whenever the validator confirms a finding.
"""
from .patch_essence import extract_essence
from .propagate import propagate_pattern

__all__ = ["extract_essence", "propagate_pattern"]
