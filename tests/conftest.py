"""
Pytest configuration and shared fixtures for unit and integration testing.
"""

from pathlib import Path
import pytest


@pytest.fixture
def root_hints_file():
    """Fixture providing path to root hints JSON file."""
    path = Path("config/root_hints.json")
    assert path.is_file()
    return path
