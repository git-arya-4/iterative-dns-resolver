"""Cold-versus-warm resolver latency experiment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import mean, median
from time import perf_counter_ns
from typing import Any


@dataclass(frozen=True)
class LatencySummary:
    samples: int
    minimum_ms: float
    median_ms: float
    mean_ms: float
    maximum_ms: float


def _summary(values: list[float]) -> LatencySummary:
    return LatencySummary(
        samples=len(values),
        minimum_ms=min(values),
        median_ms=median(values),
        mean_ms=mean(values),
        maximum_ms=max(values),
    )


def _measure(resolver: Any, domain: str, record_type: str) -> tuple[float, Any]:
    started = perf_counter_ns()
    result = resolver.resolve(domain, record_type)
    elapsed_ms = (perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, result


def run_cold_warm(
    resolver: Any,
    domain: str,
    record_type: str = "A",
    samples: int = 5,
) -> dict[str, Any]:
    """Measure cold and warm resolution latency using one resolver instance.

    Cold samples clear the resolver cache before every query. Warm samples use
    one untimed query to populate the cache, then measure repeated queries.
    """
    if samples < 1:
        raise ValueError("samples must be at least 1")
    if not hasattr(resolver, "cache") or not hasattr(resolver.cache, "clear"):
        raise TypeError("resolver must expose a cache with clear()")

    cold_ms: list[float] = []
    for _ in range(samples):
        resolver.cache.clear()
        elapsed_ms, _ = _measure(resolver, domain, record_type)
        cold_ms.append(elapsed_ms)

    resolver.cache.clear()
    _measure(resolver, domain, record_type)
    warm_ms = [_measure(resolver, domain, record_type)[0] for _ in range(samples)]

    return {
        "domain": domain,
        "record_type": record_type.upper(),
        "cold": {"latencies_ms": cold_ms, "summary": asdict(_summary(cold_ms))},
        "warm": {"latencies_ms": warm_ms, "summary": asdict(_summary(warm_ms))},
    }
