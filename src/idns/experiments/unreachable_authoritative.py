"""Experiment for observing resolver behavior when an authority is unreachable."""

from __future__ import annotations

from time import perf_counter_ns
from typing import Any, Callable

from idns.contracts.transport import TransportResult
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.model import ARecord, DNSHeader, DNSMessage, DNSName, NSRecord
from idns.wire import DNSMessageEncoder


class _UnreachableAuthoritativeTransport:
    """Deterministic Root -> TLD -> unreachable-authority scenario."""

    def __init__(self, unreachable_ip: str) -> None:
        self.unreachable_ip = unreachable_ip

    def send_query_with_fallback(self, servers, query_bytes, config=None):
        server = servers[0]
        if server.name == "test-root":
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[NSRecord(DNSName("com"), DNSName("test-tld"), 60)],
                additionals=[ARecord(DNSName("test-tld"), "192.0.2.2", 60)],
            )
        else:
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[
                    NSRecord(DNSName("example.com"), DNSName("test-authority"), 60)
                ],
                additionals=[
                    ARecord(DNSName("test-authority"), self.unreachable_ip, 60)
                ],
            )
        return TransportResult(DNSMessageEncoder.encode(message), server, 0.1)

    def send_query(self, server, query_bytes, config=None):
        raise ServerUnreachableError(
            f"authoritative server '{server.ip}:53' is unreachable"
        )


def configure_unreachable_authoritative(
    resolver: Any,
    unreachable_ip: str = "192.0.2.1",
) -> None:
    """Install the deterministic authority-failure scenario on a resolver."""
    from idns.core.cache_aware import CacheAwareResolver
    from idns.iterative.engine import IterativeEngine

    transport = _UnreachableAuthoritativeTransport(unreachable_ip)
    root_servers = [{"name": "test-root", "ipv4": "192.0.2.3"}]
    resolver.root_servers = root_servers
    resolver.resolver_chain = CacheAwareResolver(
        resolver.cache,
        IterativeEngine(transport, root_servers),
    )


def run_unreachable_authoritative(
    resolver: Any,
    domain: str,
    record_type: str = "A",
    *,
    unreachable_ip: str = "192.0.2.1",
    configure_resolver: Callable[[Any, str], None] | None = None,
) -> dict[str, Any]:
    """Run a resolution against a configured unreachable endpoint.

    ``192.0.2.1`` is from TEST-NET-1 and is reserved for documentation and
    testing. A caller can provide ``configure_resolver`` to install it as the
    resolver's authoritative/root target. No retry or timeout policy is changed.
    """
    started = perf_counter_ns()
    if configure_resolver is not None:
        configure_resolver(resolver, unreachable_ip)
    try:
        result = resolver.resolve(domain, record_type.upper())
    except Exception as error:
        return {
            "domain": domain,
            "record_type": record_type.upper(),
            "completed": False,
            "expected_failure": isinstance(
                error,
                (ServerUnreachableError, DNSTimeoutError, TimeoutError),
            ),
            "elapsed_ms": (perf_counter_ns() - started) / 1_000_000,
            "error_type": type(error).__name__,
            "error": str(error),
            "unreachable_endpoint": unreachable_ip,
        }

    return {
        "domain": domain,
        "record_type": record_type.upper(),
        "completed": True,
        "expected_failure": False,
        "elapsed_ms": (perf_counter_ns() - started) / 1_000_000,
        "query_count": int(getattr(result, "query_count", 0)),
        "rcode": getattr(result, "rcode", None),
        "is_cache_hit": bool(getattr(result, "is_cache_hit", False)),
        "unreachable_endpoint": unreachable_ip,
    }
