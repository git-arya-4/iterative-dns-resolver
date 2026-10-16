"""Reproducible demonstrations for the resolver's cache and failover behavior."""

from __future__ import annotations

import csv
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from idns.cache import InMemoryDNSCache
from idns.contracts.resolver import ResolutionContext, ResolverResult
from idns.contracts.transport import ServerAddress, TransportConfig, TransportResult
from idns.core import CoreResolver
from idns.errors import DNSTimeoutError
from idns.model import DNSHeader, DNSMessage, DNSName, NSRecord, ARecord
from idns.transport.udp import UDPTransport
from idns.wire.message_encoder import DNSMessageEncoder


class ExperimentError(Exception):
    """Raised when an experiment cannot produce a trustworthy result."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class ExperimentReport:
    name: str
    rows: list[dict[str, object]]
    notes: list[str]

    def render(self) -> str:
        lines = [f"Experiment: {self.name}"]
        for row in self.rows:
            lines.append("  " + ", ".join(f"{key}={value}" for key, value in row.items()))
        lines.extend(f"Note: {note}" for note in self.notes)
        return "\n".join(lines)

    def write_csv(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = sorted({key for row in self.rows for key in row})
        with path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)


ResolverFactory = Callable[[], CoreResolver]


def build_resolver(root_hints_path: str | Path) -> CoreResolver:
    """Build the production resolver used by live experiments."""
    return CoreResolver(
        root_hints_path=root_hints_path,
        transport=UDPTransport(),
        cache=InMemoryDNSCache(),
    )


def _resolver(factory: ResolverFactory | None, root_hints_path: str | Path) -> CoreResolver:
    return factory() if factory is not None else build_resolver(root_hints_path)


def _timed_resolve(resolver, domain: str, record_type: str) -> tuple[ResolverResult, float]:
    started = time.perf_counter()
    try:
        result = resolver.resolve(domain, record_type, ResolutionContext())
    except Exception as exc:
        raise ExperimentError(f"resolution failed for {domain} {record_type}: {exc}") from exc
    return result, (time.perf_counter() - started) * 1000


def _clear_cache(resolver) -> None:
    cache = getattr(resolver, "cache", None)
    if cache is None:
        raise ExperimentError("resolver does not expose a cache that can be reset")
    cache.clear()


def run_cold_warm(
    root_hints_path: str | Path = "config/root_hints.json",
    *,
    domain: str = "example.com",
    record_type: str = "A",
    resolver_factory: ResolverFactory | None = None,
) -> ExperimentReport:
    resolver = _resolver(resolver_factory, root_hints_path)
    _clear_cache(resolver)
    cold, cold_ms = _timed_resolve(resolver, domain, record_type)
    warm, warm_ms = _timed_resolve(resolver, domain, record_type)
    return ExperimentReport(
        "cold_warm",
        [{
            "domain": domain,
            "record_type": record_type,
            "cold_ms": round(cold_ms, 3),
            "warm_ms": round(warm_ms, 3),
            "cold_cache_hit": cold.is_cache_hit,
            "warm_cache_hit": warm.is_cache_hit,
            "cold_query_count": cold.query_count,
            "warm_query_count": warm.query_count,
            "repetitions": 2,
        }],
        ["Timing uses time.perf_counter(); one fresh cache, then one repeated query."],
    )


def run_cache_hit_ratio(
    root_hints_path: str | Path = "config/root_hints.json",
    *,
    domain: str = "example.com",
    record_type: str = "A",
    repetitions: int = 5,
    resolver_factory: ResolverFactory | None = None,
) -> ExperimentReport:
    if repetitions < 1:
        raise ExperimentError("repetitions must be at least 1")
    resolver = _resolver(resolver_factory, root_hints_path)
    _clear_cache(resolver)
    hits = misses = 0
    errors = 0
    for _ in range(repetitions):
        try:
            result, _ = _timed_resolve(resolver, domain, record_type)
            if result.is_cache_hit:
                hits += 1
            else:
                misses += 1
        except ExperimentError:
            errors += 1
    if errors:
        raise ExperimentError(f"{errors} of {repetitions} queries failed; no hit ratio reported")
    return ExperimentReport(
        "cache_hit_ratio",
        [{
            "domain": domain,
            "record_type": record_type,
            "total_queries": repetitions,
            "cache_hits": hits,
            "cache_misses": misses,
            "cache_hit_ratio": round(hits / repetitions, 4),
            "errors": errors,
        }],
        ["Hits and misses come from each returned ResolverResult.is_cache_hit value."],
    )


def run_query_count(
    root_hints_path: str | Path = "config/root_hints.json",
    *,
    domain: str = "example.com",
    record_type: str = "A",
    resolver_factory: ResolverFactory | None = None,
) -> ExperimentReport:
    resolver = _resolver(resolver_factory, root_hints_path)
    _clear_cache(resolver)
    cold, _ = _timed_resolve(resolver, domain, record_type)
    warm, _ = _timed_resolve(resolver, domain, record_type)
    return ExperimentReport(
        "query_count",
        [{
            "domain": domain,
            "record_type": record_type,
            "cold_upstream_query_count": cold.query_count,
            "warm_upstream_query_count": warm.query_count,
            "cold_cache_hit": cold.is_cache_hit,
            "warm_cache_hit": warm.is_cache_hit,
        }],
        ["query_count is the resolver's logical root/TLD/authoritative exchange count; UDP retry attempts are not included."],
    )


class _UnreachableAuthoritativeTransport:
    """Controlled transport used only for the deterministic failover experiment."""

    def __init__(self) -> None:
        self.fallback_calls = 0
        self.authoritative_attempts: list[str] = []

    @staticmethod
    def _result(message: DNSMessage, server: ServerAddress) -> TransportResult:
        return TransportResult(DNSMessageEncoder.encode(message), server, 0.1)

    def send_query_with_fallback(self, servers, query_bytes, config=None):
        self.fallback_calls += 1
        server = servers[0]
        if self.fallback_calls == 1:
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[NSRecord(DNSName("com"), DNSName("ns.com"), 300)],
                additionals=[ARecord(DNSName("ns.com"), "192.0.2.53", 300)],
            )
        else:
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[
                    NSRecord(DNSName("example.com"), DNSName("ns1.example.com"), 300),
                    NSRecord(DNSName("example.com"), DNSName("ns2.example.com"), 300),
                ],
                additionals=[
                    ARecord(DNSName("ns1.example.com"), "192.0.2.10", 300),
                    ARecord(DNSName("ns2.example.com"), "192.0.2.11", 300),
                ],
            )
        return self._result(message, server)

    def send_query(self, server, query_bytes, config=None):
        self.authoritative_attempts.append(server.ip)
        timeout = config.timeout_seconds if config is not None else 2.0
        raise DNSTimeoutError(f"{server.ip}:{server.port}", timeout)


def run_unreachable_authoritative(
    root_hints_path: str | Path = "config/root_hints.json",
    *,
    domain: str = "example.com",
    record_type: str = "A",
) -> ExperimentReport:
    transport = _UnreachableAuthoritativeTransport()
    resolver = CoreResolver(
        root_hints_path=root_hints_path,
        transport=transport,
        cache=InMemoryDNSCache(),
        transport_config=TransportConfig(timeout_seconds=0.01, max_retries=0),
    )
    started = time.perf_counter()
    try:
        resolver.resolve(domain, record_type, ResolutionContext())
    except DNSTimeoutError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return ExperimentReport(
            "unreachable_authoritative",
            [{
                "scenario": "controlled simulation",
                "attempted_authoritative_servers": len(transport.authoritative_attempts),
                "authoritative_addresses": "|".join(transport.authoritative_attempts),
                "fallback_attempted": len(transport.authoritative_attempts) > 1,
                "final_outcome": type(exc).__name__,
                "elapsed_ms": round(elapsed_ms, 3),
            }],
            ["Root and TLD responses are deterministic; both authoritative glue addresses time out."],
        )
    raise ExperimentError("controlled authoritative failure unexpectedly resolved")


def run_experiment(name: str, root_hints_path: str | Path = "config/root_hints.json", **kwargs) -> ExperimentReport:
    runners = {
        "cold_warm": run_cold_warm,
        "cache_hit_ratio": run_cache_hit_ratio,
        "query_count": run_query_count,
        "unreachable_authoritative": run_unreachable_authoritative,
    }
    try:
        runner = runners[name]
    except KeyError as exc:
        raise ExperimentError(f"unknown experiment: {name}") from exc
    return runner(root_hints_path, **kwargs)


__all__ = [
    "ExperimentError",
    "ExperimentReport",
    "run_cold_warm",
    "run_cache_hit_ratio",
    "run_query_count",
    "run_unreachable_authoritative",
    "run_experiment",
]
