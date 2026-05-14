"""Pytest configuration and shared fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the src package importable when running tests directly without an
# editable install. ``sys.path`` is the canonical location for this —
# ``os.sys.path`` works only as an alias and obscures the intent.
SRC = Path(__file__).parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def tmp_kg(tmp_path: Path):
    """Provide a fresh, initialized KG at a temporary path."""
    from lacuna.kg import KG
    db_path = tmp_path / "lacuna.db"
    kg = KG(db_path)
    kg.initialize()
    yield kg
    kg.close()


@pytest.fixture(autouse=True)
def isolate_env(tmp_path, monkeypatch):
    """Per-test temp directories for state."""
    monkeypatch.setenv("LACUNA_KG_PATH", str(tmp_path / "lacuna.db"))
    monkeypatch.setenv("LACUNA_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("LACUNA_TOOL_CACHE_DIR", str(tmp_path / "cache"))
    (tmp_path / "evidence").mkdir(exist_ok=True)
    (tmp_path / "cache").mkdir(exist_ok=True)
    yield
