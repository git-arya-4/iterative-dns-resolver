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
