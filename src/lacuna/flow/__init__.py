"""
Lacuna's custom inter-procedural data-flow engine.

Public API:

  build_call_graph(repo_root) -> CallGraph
  reachable(cg, source_fn, target_fn) -> (bool, [path])
  callers(cg, fn, transitive=True) -> set[str]
  taint_paths(cg) -> [TaintHit]

The engine produces results that recon tools can serialize for the KG and
that the validator can use to refute or confirm hypotheses with much higher
confidence than grep alone.
"""
from __future__ import annotations

from pathlib import Path

from .ast_parse import Node, parse_python_file, parse_with_tree_sitter
from .callgraph import CallGraph, CallSite, FunctionInfo
from .taint import TaintAnalyzer, TaintHit


def build_call_graph(repo_root: Path, max_files: int = 5000) -> CallGraph:
    cg = CallGraph(repo_root)
    cg.build(max_files=max_files)
    return cg


def reachable(cg: CallGraph, source_fn: str, target_fn: str,
              max_depth: int = 8) -> tuple[bool, list[str]]:
    return cg.reachable_from(source_fn, target_fn, max_depth)


def callers(cg: CallGraph, fn: str, transitive: bool = True) -> set[str]:
    return cg.callers(fn, transitive=transitive)


def taint_paths(cg: CallGraph, max_depth: int = 6) -> list[TaintHit]:
    return TaintAnalyzer(cg, max_depth=max_depth).analyze()


__all__ = [
    "CallGraph",
    "CallSite",
    "FunctionInfo",
    "Node",
    "TaintAnalyzer",
    "TaintHit",
    "build_call_graph",
    "callers",
    "parse_python_file",
    "parse_with_tree_sitter",
    "reachable",
    "taint_paths",
]
