from types import SimpleNamespace

from idns.cache import InMemoryDNSCache
from idns.contracts.cache import CacheKey
from idns.contracts.transport import TransportConfig
from idns.core import CoreResolver
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.experiments import (
    configure_unreachable_authoritative,
    run_unreachable_authoritative,
)
from idns.model import ARecord, DNSName


def test_unreachable_experiment_records_resolver_failure():
    class FailingResolver:
        def resolve(self, domain, record_type):
            raise TimeoutError("authoritative server timed out")

    configured = []
    result = run_unreachable_authoritative(
        FailingResolver(),
        "example.com",
        configure_resolver=lambda resolver, ip: configured.append(ip),
    )

    assert result["completed"] is False
    assert result["expected_failure"] is True
    assert result["error_type"] == "TimeoutError"
    assert result["error"] == "authoritative server timed out"
    assert result["unreachable_endpoint"] == "192.0.2.1"
    assert configured == ["192.0.2.1"]


def test_unreachable_experiment_classifies_project_timeout_as_expected():
    class FailingResolver:
        def resolve(self, domain, record_type):
            raise DNSTimeoutError("192.0.2.1:53", 2.0)

    result = run_unreachable_authoritative(FailingResolver(), "example.com")

    assert result["completed"] is False
    assert result["expected_failure"] is True
    assert result["error_type"] == "DNSTimeoutError"


def test_unreachable_experiment_reports_unexpected_success():
    class SuccessfulResolver:
        def resolve(self, domain, record_type):
            return SimpleNamespace(query_count=2, rcode=0, is_cache_hit=False)

    result = run_unreachable_authoritative(SuccessfulResolver(), "example.com", "a")

    assert result["completed"] is True
    assert result["expected_failure"] is False
    assert result["record_type"] == "A"
    assert result["query_count"] == 2


def test_unreachable_experiment_does_not_misclassify_unexpected_errors():
    class BrokenResolver:
        def resolve(self, domain, record_type):
            raise ValueError("invalid resolver state")

    result = run_unreachable_authoritative(BrokenResolver(), "example.com")

    assert result["completed"] is False
    assert result["expected_failure"] is False
    assert result["error_type"] == "ValueError"
    assert result["error"] == "invalid resolver state"


def test_unreachable_experiment_reaches_authority_after_root_and_tld():
    resolver = CoreResolver(cache=InMemoryDNSCache())

    result = run_unreachable_authoritative(
        resolver,
        "example.com",
        configure_resolver=lambda target, _: configure_unreachable_authoritative(target),
    )

    assert result["completed"] is False
    assert result["error_type"] == "ServerUnreachableError"
    assert result["unreachable_endpoint"] == "192.0.2.1"


def test_unreachable_experiment_builds_referrals_for_non_example_domains():
    resolver = CoreResolver(cache=InMemoryDNSCache())

    result = run_unreachable_authoritative(
        resolver,
        "www.acme.org",
        configure_resolver=configure_unreachable_authoritative,
    )

    assert result["completed"] is False
    assert result["error_type"] == "ServerUnreachableError"
    assert result["query_count"] == 2
    assert result["queried_servers"] == ["192.0.2.1"]
    assert any(
        "test-authority.acme.org" in event for event in result["trace_log"]
    )


def test_unreachable_experiment_rejects_single_label_domains_explicitly():
    result = run_unreachable_authoritative(
        CoreResolver(cache=InMemoryDNSCache()),
        "localhost",
        configure_resolver=configure_unreachable_authoritative,
    )

    assert result["completed"] is False
    assert result["expected_failure"] is False
    assert result["error_type"] == "ValueError"
    assert "at least two labels" in result["error"]


def test_unreachable_experiment_bypasses_cache_without_mutating_it():
    cache = InMemoryDNSCache()
    key = CacheKey.from_query("cached.acme.org", "A")
    cached_record = ARecord(DNSName("cached.acme.org"), "203.0.113.10", 300)
    cache.put_positive(key, [cached_record])
    resolver = CoreResolver(cache=cache)
    original_chain = resolver.resolver_chain

    result = run_unreachable_authoritative(
        resolver,
        "cached.acme.org",
        configure_resolver=configure_unreachable_authoritative,
    )

    assert result["completed"] is False
    assert result["error_type"] == "ServerUnreachableError"
    assert cache.get(key).records == [cached_record]
    assert resolver.resolver_chain is original_chain


def test_configure_unreachable_authoritative_preserves_transport_config():
    transport_config = TransportConfig(
        timeout_seconds=0.25,
        max_retries=7,
        enable_tcp_fallback=False,
        buffer_size=1232,
    )
    resolver = CoreResolver(
        transport=object(),
        cache=InMemoryDNSCache(),
        transport_config=transport_config,
    )

    configure_unreachable_authoritative(resolver)

    iterative_resolver = resolver.resolver_chain.iterative_resolver
    assert iterative_resolver.transport_config is transport_config
    assert iterative_resolver.bootstrap.transport_config is transport_config


def test_unreachable_experiment_includes_failure_query_metadata():
    class FailingResolver:
        def resolve(self, domain, record_type, context=None):
            context.query_count = 4
            context.queried_servers.extend(["192.0.2.3", "192.0.2.1"])
            context.trace_log.extend(["root query", "authority query"])
            raise ServerUnreachableError("authoritative endpoint unavailable")

    result = run_unreachable_authoritative(FailingResolver(), "acme.org")

    assert result["completed"] is False
    assert result["expected_failure"] is True
    assert result["query_count"] == 4
    assert result["queried_servers"] == ["192.0.2.3", "192.0.2.1"]
    assert result["trace_log"] == ["root query", "authority query"]
