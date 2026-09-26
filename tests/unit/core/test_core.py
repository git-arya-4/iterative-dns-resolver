"""
Unit test verifying CoreResolverScaffold initialization and root hints loading in idns.core.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from idns.cache import InMemoryDNSCache
from idns.contracts.resolver import ResolutionContext
from idns.core import CoreResolverScaffold
from idns.errors import CNAMELoopError, ConfigError, MaxDepthExceededError


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


def test_core_resolver_preserves_injected_dependencies():
    codec = MagicMock()
    transport = MagicMock()
    cache = InMemoryDNSCache()

    scaffold = CoreResolverScaffold(
        codec=codec,
        transport=transport,
        cache=cache,
    )

    assert scaffold.codec is codec
    assert scaffold.transport is transport
    assert scaffold.cache is cache


def test_core_resolver_accepts_or_constructs_context():
    scaffold = CoreResolverScaffold()
    supplied_context = ResolutionContext(max_depth=3)

    assert scaffold.create_context(supplied_context) is supplied_context
    created_context = scaffold.create_context()
    assert isinstance(created_context, ResolutionContext)
    assert created_context.max_depth == 10


def test_resolution_context_depth_behavior_is_preserved():
    context = ResolutionContext(max_depth=1)
    context.increment_depth()
    assert context.current_depth == 1

    with pytest.raises(MaxDepthExceededError):
        context.increment_depth()


def test_resolution_context_cname_loop_behavior_is_preserved():
    context = ResolutionContext()
    context.record_cname("Example.COM.")
    assert context.cname_chain == ["example.com."]

    with pytest.raises(CNAMELoopError):
        context.record_cname("EXAMPLE.COM.")


def test_resolver_construction_does_not_use_network_or_cache():
    transport = MagicMock()
    cache = MagicMock()

    CoreResolverScaffold(transport=transport, cache=cache)

    transport.assert_not_called()
    cache.assert_not_called()


def test_resolver_skeleton_does_not_invoke_dependencies_or_forward():
    codec = MagicMock()
    transport = MagicMock()
    cache = MagicMock()
    scaffold = CoreResolverScaffold(
        codec=codec,
        transport=transport,
        cache=cache,
    )

    with pytest.raises(NotImplementedError):
        scaffold.resolve("example.com", "A")

    codec.assert_not_called()
    transport.assert_not_called()
    cache.assert_not_called()
