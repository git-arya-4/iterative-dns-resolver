from dataclasses import dataclass

import pytest

from idns.cache import InMemoryDNSCache
from idns.contracts.resolver import ResolverResult
from idns.experiments import (
    ExperimentError,
    run_cache_hit_ratio,
    run_cold_warm,
    run_query_count,
    run_unreachable_authoritative,
)
from idns.model import ARecord, DNSName


@dataclass
class ControlledResolver:
    cache: InMemoryDNSCache

    def resolve(self, domain_name, record_type, context):
        from idns.contracts.cache import CacheKey

        entry = self.cache.get(CacheKey.from_query(domain_name, record_type))
        if entry is not None:
            return ResolverResult(domain_name, record_type, list(entry.records), is_cache_hit=True)
        answer = ARecord(DNSName(domain_name), "192.0.2.1", 300)
        self.cache.put_positive(CacheKey.from_query(domain_name, record_type), [answer])
        return ResolverResult(domain_name, record_type, [answer], query_count=3)


def factory():
    return ControlledResolver(InMemoryDNSCache())


def test_cold_warm_resets_cache_and_reports_hits():
    row = run_cold_warm(resolver_factory=factory).rows[0]
    assert row["cold_cache_hit"] is False
    assert row["warm_cache_hit"] is True
    assert row["cold_query_count"] == 3


def test_cache_hit_ratio_counts_returned_results():
    row = run_cache_hit_ratio(repetitions=4, resolver_factory=factory).rows[0]
    assert row["total_queries"] == 4
    assert row["cache_hits"] == 3
    assert row["cache_misses"] == 1
    assert row["cache_hit_ratio"] == 0.75


def test_cache_hit_ratio_rejects_invalid_repetitions():
    with pytest.raises(ExperimentError):
        run_cache_hit_ratio(repetitions=0, resolver_factory=factory)


def test_query_count_reports_cold_and_warm_semantics():
    row = run_query_count(resolver_factory=factory).rows[0]
    assert row["cold_upstream_query_count"] == 3
    assert row["warm_upstream_query_count"] == 0
    assert row["warm_cache_hit"] is True


def test_unreachable_authoritative_is_a_deterministic_failover_simulation(root_hints_file):
    row = run_unreachable_authoritative(root_hints_file).rows[0]
    assert row["scenario"] == "controlled simulation"
    assert row["attempted_authoritative_servers"] == 2
    assert row["fallback_attempted"] is True
    assert row["final_outcome"] == "DNSTimeoutError"
