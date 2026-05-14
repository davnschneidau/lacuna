"""
Lacuna v3 Layer 2: precision static analysis.

Each tool here produces *precision findings* — high-confidence leads that
hunters convert into hypotheses, and validators confirm. The tools target
bug classes where v2's data-flow engine alone isn't precise enough:

  integer_range:   CWE-190/191 — over/underflow into allocations and indices
  lifetime:        CWE-416/415/562/672 — UAF, double-free, dangling pointer
  format_string:   CWE-134 — format-string sinks with non-literal format args
  type_confusion:  CWE-843 — casts/coercions without runtime type guarantees
  allocator_map:   meta — identifies allocators in use (informs other tools)

Each module exposes:
  analyze(repo_root: Path, **opts) -> {summary, findings[]}

Findings are dicts with: kind, repo, file, line, function_qual, cwe,
detail_md, evidence, confidence, cve_hint (forward-compat).

All analyzers are pure-Python on top of the v2 flow engine (tree-sitter
+ stdlib ast). They will not catch every CVE — that's what Layer 3 is
for. They will catch the long tail of obvious bugs cheaply.
"""

from .allocator_map import analyze as analyze_allocator_map
from .format_string import analyze as analyze_format_string
from .integer_range import analyze as analyze_integer_range
from .lifetime import analyze as analyze_lifetime
from .type_confusion import analyze as analyze_type_confusion

__all__ = [
    "analyze_allocator_map",
    "analyze_format_string",
    "analyze_integer_range",
    "analyze_lifetime",
    "analyze_type_confusion",
]
