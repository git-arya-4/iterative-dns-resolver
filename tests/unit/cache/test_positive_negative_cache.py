from idns.cache import InMemoryDNSCache
from idns.contracts.cache import CacheConfig, CacheKey
from idns.model import DNSName, SOARecord
from idns.model.records import ARecord


def make_soa(ttl: int, minimum: int) -> SOARecord:
    return SOARecord(
        name=DNSName("example.com"),
        mname=DNSName("ns1.example.com"),
        rname=DNSName("hostmaster.example.com"),
        serial=1,
        refresh=3600,
        retry=600,
        expire=86400,
        minimum=minimum,
        ttl=ttl,
    )


def test_put_positive_uses_lowest_rrset_ttl():
    cache = InMemoryDNSCache(clock=lambda: 100.0)
    key = CacheKey("example.com", "A")
    records = [
        ARecord(DNSName("example.com"), "192.0.2.1", ttl=120),
        ARecord(DNSName("example.com"), "192.0.2.2", ttl=30),
    ]

    cache.put_positive(key, records)

    entry = cache.get(key)
    assert entry is not None
    assert entry.records == records
    assert entry.ttl_seconds == 30


def test_put_negative_stores_nxdomain_with_rfc2308_ttl():
    cache = InMemoryDNSCache(CacheConfig(negative_ttl_seconds=300), clock=lambda: 100.0)
    key = CacheKey("missing.example.com", "A")

    cache.put_negative(key, is_nxdomain=True, soa_record=make_soa(ttl=600, minimum=45))

    entry = cache.get(key)
    assert entry is not None
    assert entry.is_negative is True
    assert entry.is_nxdomain is True
    assert entry.ttl_seconds == 45


def test_put_negative_stores_nodata_with_fallback_ttl_without_soa():
    cache = InMemoryDNSCache(CacheConfig(negative_ttl_seconds=90), clock=lambda: 100.0)
    key = CacheKey("example.com", "MX")

    cache.put_negative(key, is_nxdomain=False)

    entry = cache.get(key)
    assert entry is not None
    assert entry.is_negative is True
    assert entry.is_nxdomain is False
    assert entry.ttl_seconds == 90


def test_get_evicts_expired_negative_entry():
    now = [100.0]
    cache = InMemoryDNSCache(clock=lambda: now[0])
    key = CacheKey("missing.example.com", "A")
    cache.put_negative(key, is_nxdomain=True, ttl_seconds=10)
    now[0] = 110.0

    assert cache.get(key) is None
    assert cache.get_stats().evictions == 1
