"""Tests for CacheAwareResolver."""

import pytest
from idns.core.cache_aware import CacheAwareResolver
from idns.contracts.cache import CacheEntry, CacheKey
from idns.contracts.resolver import ResolutionContext, ResolverResult
from idns.model import ARecord, DNSName, CNAMERecord
from idns.cache import InMemoryDNSCache


class MockIterativeResolver:
    def __init__(self):
        self.calls = 0

    def resolve(self, domain_name: str, record_type: str = "A", context=None):
        self.calls += 1
        if domain_name == "nx.example":
            return ResolverResult(domain_name, record_type, answers=[], is_nxdomain=True, rcode=3)
        if domain_name == "nodata.example":
            return ResolverResult(domain_name, record_type, answers=[], is_nxdomain=False, rcode=0)
        
        return ResolverResult(domain_name, record_type, answers=[
            ARecord(DNSName(domain_name), "1.1.1.1", 300)
        ], is_nxdomain=False, rcode=0)


def test_cache_hit_bypasses_iterative():
    cache = InMemoryDNSCache()
    key = CacheKey.from_query("hit.example", "A")
    cache.put(key, CacheEntry.create_positive(key, [ARecord(DNSName("hit.example"), "2.2.2.2", 300)], 300))
    
    iterative = MockIterativeResolver()
    resolver = CacheAwareResolver(cache, iterative)
    
    res = resolver.resolve("hit.example", "A")
    assert res.is_cache_hit
    assert len(res.answers) == 1
    assert res.answers[0].address == "2.2.2.2"
    assert iterative.calls == 0


def test_cache_miss_calls_iterative_and_caches():
    cache = InMemoryDNSCache()
    iterative = MockIterativeResolver()
    resolver = CacheAwareResolver(cache, iterative)
    
    res = resolver.resolve("miss.example", "A")
    assert not res.is_cache_hit
    assert len(res.answers) == 1
    assert iterative.calls == 1
    
    # Second call should hit cache
    res2 = resolver.resolve("miss.example", "A")
    assert res2.is_cache_hit
    assert iterative.calls == 1


def test_negative_caching_nxdomain():
    cache = InMemoryDNSCache()
    iterative = MockIterativeResolver()
    resolver = CacheAwareResolver(cache, iterative)
    
    res = resolver.resolve("nx.example", "A")
    assert not res.is_cache_hit
    assert res.is_nxdomain
    assert iterative.calls == 1
    
    # Query AAAA for same name -> should be cached as NXDOMAIN (name level)
    res2 = resolver.resolve("nx.example", "AAAA")
    assert res2.is_cache_hit
    assert res2.is_nxdomain
    assert iterative.calls == 1


def test_negative_caching_nodata():
    cache = InMemoryDNSCache()
    iterative = MockIterativeResolver()
    resolver = CacheAwareResolver(cache, iterative)
    
    res = resolver.resolve("nodata.example", "A")
    assert not res.is_cache_hit
    assert not res.is_nxdomain
    assert len(res.answers) == 0
    assert iterative.calls == 1
    
    # Query AAAA for same name -> SHOULD NOT be cached as NXDOMAIN or NODATA (qtype specific)
    res2 = resolver.resolve("nodata.example", "AAAA")
    assert not res2.is_cache_hit
    assert iterative.calls == 2


def test_cname_target_rrset_is_cached_separately():
    class SameResponseResolver:
        def __init__(self):
            self.calls = 0

        def resolve(self, domain_name, record_type="A", context=None):
            self.calls += 1
            return ResolverResult(domain_name, record_type, answers=[
                CNAMERecord(DNSName("alias.example"), DNSName("target.example"), 100),
                ARecord(DNSName("target.example"), "1.2.3.4", 50),
            ])

    cache = InMemoryDNSCache()
    iterative = SameResponseResolver()
    resolver = CacheAwareResolver(cache, iterative)

    first = resolver.resolve("alias.example", "A")
    assert first.answers[-1].address == "1.2.3.4"

    alias_entry = cache.get(CacheKey.from_query("alias.example", "A"))
    target_entry = cache.get(CacheKey.from_query("target.example", "A"))
    assert alias_entry is not None
    assert alias_entry.records == [CNAMERecord(
        DNSName("alias.example"), DNSName("target.example"), 100
    )]
    assert alias_entry.ttl_seconds == 100
    assert target_entry is not None
    assert target_entry.records == [ARecord(DNSName("target.example"), "1.2.3.4", 50)]
    assert target_entry.ttl_seconds == 50

    iterative.calls = 0
    second = resolver.resolve("target.example", "A")
    assert second.is_cache_hit
    assert second.answers[0].address == "1.2.3.4"
    assert iterative.calls == 0


def test_cname_target_rrsets_are_cached_for_same_response_multi_hop():
    class SameResponseResolver:
        def __init__(self):
            self.calls = 0

        def resolve(self, domain_name, record_type="A", context=None):
            self.calls += 1
            return ResolverResult(domain_name, record_type, answers=[
                CNAMERecord(DNSName("alias.example"), DNSName("target1.example"), 100),
                CNAMERecord(DNSName("target1.example"), DNSName("target2.example"), 80),
                ARecord(DNSName("target2.example"), "1.2.3.4", 50),
            ])

    cache = InMemoryDNSCache()
    iterative = SameResponseResolver()
    resolver = CacheAwareResolver(cache, iterative)

    first = resolver.resolve("alias.example", "A")
    assert [record.record_type for record in first.answers] == ["CNAME", "CNAME", "A"]
    iterative.calls = 0

    target1 = resolver.resolve("target1.example", "A")
    target2 = resolver.resolve("target2.example", "A")
    assert target1.is_cache_hit
    assert target2.is_cache_hit
    assert target2.answers[0].address == "1.2.3.4"
    assert iterative.calls == 0
