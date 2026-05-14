"""
Lacuna v3 Layer 4: patch-diff and variant-search infrastructure.

Mythos-style observation: the fix for a bug is evidence about the bug
class. Most fix commits address ONE manifestation; the variant space
survives. v2 found one bug at a time; v3 finds one bug and uses it to
find N more.

Modules:
  patch_essence:  given a git commit (or diff text), distill the bug-class
                  abstraction and generate a semgrep-style rule that
                  matches the BEFORE pattern.

  propagate:      given a generated rule, run it across the codebase to
                  find sibling sites that match the same pattern.

The combined workflow:
  1. `patch_essence(commit_sha)` → rule
  2. `propagate(rule)` → matches
  3. Each match becomes a hypothesis at confidence 0.6 with parent_finding_id

Without external CVE corpus, this works on the user's own git history.
The `patch-archaeologist` agent runs across `recent_security_commits`;
the `variant-hunter` agent runs whenever the validator confirms a finding.
"""
from .patch_essence import extract_essence, generate_rule
from .propagate import propagate_pattern

__all__ = ["extract_essence", "generate_rule", "propagate_pattern"]
