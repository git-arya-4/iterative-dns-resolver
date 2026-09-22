"""
Unit test verifying CoreResolverScaffold initialization and root hints loading in idns.core.
"""

from pathlib import Path
import pytest

from idns.core import CoreResolverScaffold
from idns.errors import ConfigError


def test_core_resolver_scaffold_root_hints():
    """Verify CoreResolverScaffold loads official root hints configuration."""
    hints_file = Path("config/root_hints.json")
    assert hints_file.exists()

    scaffold = CoreResolverScaffold(root_hints_path=hints_file)
    assert len(scaffold.root_servers) == 13
    assert scaffold.root_servers[0]["name"] == "a.root-servers.net"
    assert scaffold.root_servers[0]["ipv4"] == "198.41.0.4"


def test_core_resolver_invalid_hints_file(tmp_path):
    """Verify ConfigError is raised when root hints file is missing or invalid."""
    scaffold = CoreResolverScaffold()
    
    with pytest.raises(ConfigError) as exc_info:
        scaffold.load_root_hints(tmp_path / "nonexistent.json")
    assert "not found" in str(exc_info.value)

    invalid_json = tmp_path / "bad.json"
    invalid_json.write_text("{bad json}")
    with pytest.raises(ConfigError) as exc_info:
        scaffold.load_root_hints(invalid_json)
    assert "Invalid JSON" in str(exc_info.value)


def test_core_resolver_resolve_raises_not_implemented():
    """Verify resolve method raises NotImplementedError at Phase 0."""
    scaffold = CoreResolverScaffold()
    with pytest.raises(NotImplementedError) as exc_info:
        scaffold.resolve("example.com", "A")
    assert "Phase 5" in str(exc_info.value)
