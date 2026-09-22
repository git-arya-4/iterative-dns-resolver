"""
Unit tests for the DNS Cache Subsystem API contract (Sub-task 1.6).
"""

import time
import pytest

from idns.contracts.cache import (
    CacheKey,
    CacheEntry,
    CacheConfig,
    CacheStats,
    DNSCacheProtocol,
    compute_rfc2308_ttl,
)
from idns.model.name import DNSName
from idns.model.records import SOARecord


def test_cache_key_canonicalization():
    """Verify CacheKey canonicalization rules for casing and trailing dots."""
    # Test string input with uppercase and trailing dot
    key1 = CacheKey(domain_name="EXAMPLE.COM.", record_type="a", dns_class="in")
    canonical1 = key1.canonical()
    assert canonical1.domain_name == "example.com"
    assert canonical1.record_type == "A"
    assert canonical1.dns_class == "IN"

    # Test DNSName input
    dns_name = DNSName("sub.Example.ORG.")
    key2 = CacheKey(domain_name=dns_name, record_type="aaaa")
    canonical2 = key2.canonical()
    assert canonical2.domain_name == "sub.example.org"
    assert canonical2.record_type == "AAAA"
    assert canonical2.dns_class == "IN"

    # Test equality of equivalent keys when canonicalized
    key_alt = CacheKey("SUB.EXAMPLE.ORG", "AAAA")
    assert canonical2 == key_alt.canonical()
    assert hash(canonical2) == hash(key_alt.canonical())


def test_cache_key_from_query():
    """Verify from_query helper creates canonical keys."""
    key = CacheKey.from_query("WWW.GOOGLE.COM.", record_type="cname")
    assert key.domain_name == "www.google.com"
    assert key.record_type == "CNAME"
    assert key.dns_class == "IN"


def test_cache_config():
    """Verify CacheConfig defaults and custom attributes."""
    cfg = CacheConfig()
    assert cfg.enabled is True
    assert cfg.max_entries == 10000
    assert cfg.negative_ttl_seconds == 300
    assert cfg.rfc2308_enabled is True

    custom_cfg = CacheConfig(
        enabled=False,
        max_entries=500,
        negative_ttl_seconds=60,
        rfc2308_enabled=False,
    )
    assert custom_cfg.enabled is False
    assert custom_cfg.max_entries == 500
    assert custom_cfg.negative_ttl_seconds == 60
    assert custom_cfg.rfc2308_enabled is False


def test_cache_entry_positive():
    """Verify positive CacheEntry creation, expiration check, and remaining TTL."""
    key = CacheKey("example.com", "A")
    entry = CacheEntry.create_positive(
        key=key,
        records=["93.184.216.34"],
        ttl_seconds=100,
        creation_timestamp=1000.0,
    )

    assert entry.is_negative is False
    assert entry.is_nxdomain is False
    assert entry.ttl_seconds == 100
    assert entry.records == ["93.184.216.34"]

    # TTL not expired at timestamp 1050
    assert entry.is_expired(current_timestamp=1050.0) is False
    assert entry.remaining_ttl(current_timestamp=1050.0) == 50

    # TTL expired at timestamp 1100
    assert entry.is_expired(current_timestamp=1100.0) is True
    assert entry.remaining_ttl(current_timestamp=1100.0) == 0

    # Negative remaining TTL clamped to 0
    assert entry.remaining_ttl(current_timestamp=1200.0) == 0


def test_cache_entry_negative():
    """Verify negative CacheEntry creation for NXDOMAIN and NODATA."""
    key = CacheKey("nonexistent.example.com", "A")
    nx_entry = CacheEntry.create_negative(
        key=key,
        is_nxdomain=True,
        ttl_seconds=60,
        creation_timestamp=500.0,
    )
    assert nx_entry.is_negative is True
    assert nx_entry.is_nxdomain is True
    assert nx_entry.records == []
    assert nx_entry.remaining_ttl(current_timestamp=520.0) == 40

    nodata_entry = CacheEntry.create_negative(
        key=key,
        is_nxdomain=False,
        ttl_seconds=60,
        creation_timestamp=500.0,
    )
    assert nodata_entry.is_negative is True
    assert nodata_entry.is_nxdomain is False


def test_compute_rfc2308_ttl():
    """Verify RFC 2308 negative TTL computation: min(SOA.ttl, SOA.minimum)."""
    # Case 1: SOA.minimum (60) is smaller than SOA.ttl (300)
    soa1 = SOARecord(
        name=DNSName("example.com"),
        mname=DNSName("ns1.example.com"),
        rname=DNSName("hostmaster.example.com"),
        serial=1,
        refresh=3600,
        retry=600,
        expire=86400,
        minimum=60,
        ttl=300,
    )
    assert compute_rfc2308_ttl(soa1, max_negative_ttl=300) == 60

    # Case 2: SOA.ttl (45) is smaller than SOA.minimum (300)
    soa2 = SOARecord(
        name=DNSName("example.com"),
        mname=DNSName("ns1.example.com"),
        rname=DNSName("hostmaster.example.com"),
        serial=1,
        refresh=3600,
        retry=600,
        expire=86400,
        minimum=300,
        ttl=45,
    )
    assert compute_rfc2308_ttl(soa2, max_negative_ttl=300) == 45

    # Case 3: SOA values exceed max_negative_ttl (clamped to max_negative_ttl)
    soa3 = SOARecord(
        name=DNSName("example.com"),
        mname=DNSName("ns1.example.com"),
        rname=DNSName("hostmaster.example.com"),
        serial=1,
        refresh=3600,
        retry=600,
        expire=86400,
        minimum=3600,
        ttl=7200,
    )
    assert compute_rfc2308_ttl(soa3, max_negative_ttl=300) == 300

    # Case 4: No SOA record provided (falls back to max_negative_ttl)
    assert compute_rfc2308_ttl(None, max_negative_ttl=120) == 120


def test_cache_stats():
    """Verify CacheStats hit ratio calculations."""
    stats = CacheStats()
    assert stats.hit_ratio == 0.0

    stats.hits = 3
    stats.misses = 1
    assert stats.hit_ratio == 0.75

    stats.evictions = 5
    assert stats.evictions == 5


def test_cache_protocol():
    """Verify an implementation satisfies runtime_checkable DNSCacheProtocol."""
    class DummyCache:
        def __init__(self):
            self.store = {}
            self.stats = CacheStats()

        def get(self, key: CacheKey):
            return self.store.get(key.canonical())

        def put(self, key: CacheKey, entry: CacheEntry) -> None:
            self.store[key.canonical()] = entry

        def remove(self, key: CacheKey) -> bool:
            return self.store.pop(key.canonical(), None) is not None

        def clear(self) -> None:
            self.store.clear()

        def get_stats(self) -> CacheStats:
            return self.stats

    cache = DummyCache()
    assert isinstance(cache, DNSCacheProtocol)
