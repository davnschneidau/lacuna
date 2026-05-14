"""Lacuna report generation."""
from .generator import write_reports
from .sarif_emitter import emit_sarif

__all__ = ["emit_sarif", "write_reports"]
