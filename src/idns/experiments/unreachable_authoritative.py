"""Experiment for observing resolver behavior when an authority is unreachable."""

from __future__ import annotations

from time import perf_counter_ns
from typing import Any


def run_unreachable_authoritative(
    resolver: Any,
    domain: str,
    record_type: str = "A",
) -> dict[str, Any]:
    """Run a resolution and record failure behavior.

    The supplied resolver must be configured with the unreachable authoritative
    endpoint before this function is called. No retry or timeout policy is
    changed by the experiment.
    """
    started = perf_counter_ns()
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
    }
