"""Experiment for observing resolver behavior when an authority is unreachable."""

from __future__ import annotations

from time import perf_counter_ns
from typing import Any, Callable


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
            "expected_failure": True,
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
