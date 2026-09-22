"""
Unit test verifying package imports from idns.*, CLI parser, and module placeholders.
"""

import pytest
from idns.cli import build_parser, main


def test_import_contracts():
    """Verify all contracts and shared types import cleanly from idns.contracts."""
    import idns.contracts
    from idns.contracts import (
        DNSCodecProtocol,
        DNSTransportProtocol,
        ServerAddress,
        TransportConfig,
        TransportResult,
        DNSCacheProtocol,
        CacheKey,
        CacheEntry,
        CacheStats,
        CacheConfig,
        compute_rfc2308_ttl,
        DNSResolverProtocol,
        ResolutionContext,
        ResolverResult,
    )
    assert DNSCodecProtocol is not None
    assert DNSTransportProtocol is not None
    assert DNSCacheProtocol is not None
    assert CacheConfig is not None
    assert compute_rfc2308_ttl is not None
    assert DNSResolverProtocol is not None


def test_import_errors():
    """Verify exception hierarchy imports from idns.errors."""
    import idns.errors
    from idns.errors import (
        DNSError,
        ConfigError,
        CodecError,
        TransportError,
        DNSTimeoutError,
        ServerUnreachableError,
        ResolutionError,
        CNAMELoopError,
        MaxDepthExceededError,
        ReferralError,
        CacheError,
        ServerError,
    )

    err = DNSError("test error")
    assert str(err) == "test error"

    timeout_err = DNSTimeoutError(server="198.41.0.4", timeout=2.0)
    assert "198.41.0.4" in str(timeout_err)

    cname_err = CNAMELoopError(["example.com", "alias.com", "example.com"])
    assert "CNAME loop detected" in str(cname_err)

    depth_err = MaxDepthExceededError(max_depth=10, current_depth=11)
    assert "10" in str(depth_err)


def test_import_idns_packages():
    """Verify all subsystem package placeholders import cleanly under idns.*."""
    import idns
    import idns.model
    import idns.wire
    import idns.transport
    import idns.iterative
    import idns.cache
    import idns.server
    import idns.observability
    import idns.extensions

    assert idns.__version__ == "0.1.0"


def test_cli_help(capsys):
    """Verify CLI parser builds and displays help without error."""
    parser = build_parser()
    assert parser.prog == "idns-resolver"

    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Iterative DNS Resolver with Caching" in captured.out


def test_cli_version(capsys):
    """Verify CLI version option."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "0.1.0-foundation" in captured.out or "0.1.0-foundation" in captured.err
