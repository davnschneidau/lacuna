"""
Lacuna v3 Layer 3: dynamic confirmation oracles.

These oracles produce *ground-truth evidence* — crashing inputs, parser
divergence, symbolic-execution witnesses. Used by validators when static
analysis can't reach confident yes/no.

Modules:
  sanitizer_build  Auto-detect build system, build with ASan/UBSan
  fuzzer           libFuzzer / AFL++ wrapper for crash discovery
  symex            angr wrapper for path reachability with witness input
  differential     Multi-parser differential testing (HTTP smuggling etc.)

All oracles return the same envelope: {summary, status, findings|crashes|...}
"""
from .sanitizer_build import build as sanitizer_build
from .fuzzer import fuzz_function
from .symex import symex_reach
from .differential import differential_parse

__all__ = [
    "sanitizer_build", "fuzz_function", "symex_reach", "differential_parse",
]
