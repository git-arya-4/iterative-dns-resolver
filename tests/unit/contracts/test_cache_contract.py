"""Contract tests for subtask 1.6 cache API."""

from idns.contracts.cache import (
    CacheConfig, CacheEntry, CacheKey, CacheStats, DNSCacheProtocol,
    compute_rfc2308_ttl,
)


def test_cache_key_and_entry_contract():
    key = CacheKey.from_query("WWW.Example.COM.", "a")
    assert key == CacheKey("www.example.com", "A", "IN")
    entry = CacheEntry.create_positive(key, ["answer"], 60, creation_timestamp=100.0)
    assert entry.remaining_ttl(125.0) == 35
    assert not entry.is_expired(125.0)
    assert entry.is_expired(160.0)


def test_negative_cache_contract_and_rfc2308_ttl():
    key = CacheKey("missing.example", "A")
    entry = CacheEntry.create_negative(key, is_nxdomain=True, ttl_seconds=30, creation_timestamp=10.0)
    assert entry.is_negative and entry.is_nxdomain and entry.records == []
    assert compute_rfc2308_ttl(type("SOA", (), {"ttl": 300, "minimum": 45})()) == 45
    assert compute_rfc2308_ttl(None, 90) == 90


def test_cache_config_stats_and_protocol_shape():
    assert CacheConfig().max_entries == 10000
    stats = CacheStats(hits=3, misses=1)
    assert stats.hit_ratio == 0.75

    class DummyCache:
        def get(self, key): return None
        def put(self, key, entry): pass
        def remove(self, key): return False
        def clear(self): pass
        def get_stats(self): return CacheStats()

    assert isinstance(DummyCache(), DNSCacheProtocol)
