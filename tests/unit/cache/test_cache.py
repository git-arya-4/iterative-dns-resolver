from idns.cache import InMemoryDNSCache
from idns.contracts.cache import CacheEntry, CacheKey, DNSCacheProtocol


def make_entry(key: CacheKey, record: str = "answer") -> CacheEntry:
    return CacheEntry.create_positive(key, [record], ttl_seconds=300)


def test_empty_cache_is_a_miss():
    cache = InMemoryDNSCache()

    assert cache.get(CacheKey("example.com")) is None
    assert cache.get_stats().misses == 1
    assert cache.get_stats().hits == 0
    assert cache.get_stats().size == 0


def test_put_then_get_uses_canonical_key():
    cache = InMemoryDNSCache()
    key = CacheKey("Example.COM.", "a", "in")
    entry = make_entry(key)

    cache.put(key, entry)

    assert cache.get(CacheKey("example.com", "A", "IN")) is entry
    assert cache.get_stats().hits == 1
    assert cache.get_stats().size == 1


def test_put_replaces_existing_key():
    cache = InMemoryDNSCache()
    key = CacheKey("example.com")
    first = make_entry(key, "first")
    second = make_entry(key, "second")

    cache.put(key, first)
    cache.put(CacheKey("EXAMPLE.COM."), second)

    assert cache.get(key) is second
    assert cache.get_stats().size == 1


def test_remove_existing_key():
    cache = InMemoryDNSCache()
    key = CacheKey("example.com")
    cache.put(key, make_entry(key))

    assert cache.remove(CacheKey("EXAMPLE.COM.")) is True
    assert cache.get(key) is None
    assert cache.get_stats().size == 0
    assert cache.get_stats().evictions == 1


def test_remove_missing_key():
    cache = InMemoryDNSCache()

    assert cache.remove(CacheKey("missing.example")) is False
    assert cache.get_stats().evictions == 0


def test_clear_removes_all_entries():
    cache = InMemoryDNSCache()
    cache.put(CacheKey("one.example"), make_entry(CacheKey("one.example")))
    cache.put(CacheKey("two.example"), make_entry(CacheKey("two.example")))

    cache.clear()

    assert cache.get(CacheKey("one.example")) is None
    assert cache.get(CacheKey("two.example")) is None
    assert cache.get_stats().size == 0


def test_record_types_are_independent_keys():
    cache = InMemoryDNSCache()
    a_key = CacheKey("example.com", "A")
    aaaa_key = CacheKey("example.com", "AAAA")
    cache.put(a_key, make_entry(a_key, "a-answer"))
    cache.put(aaaa_key, make_entry(aaaa_key, "aaaa-answer"))

    assert cache.get(a_key).records == ["a-answer"]
    assert cache.get(aaaa_key).records == ["aaaa-answer"]
    assert cache.get_stats().size == 2


def test_dns_classes_are_independent_keys():
    cache = InMemoryDNSCache()
    in_key = CacheKey("example.com", "A", "IN")
    other_key = CacheKey("example.com", "A", "CH")
    cache.put(in_key, make_entry(in_key, "in-answer"))
    cache.put(other_key, make_entry(other_key, "ch-answer"))

    assert cache.get(in_key).records == ["in-answer"]
    assert cache.get(other_key).records == ["ch-answer"]
    assert cache.get_stats().size == 2


def test_cache_satisfies_protocol_and_tracks_basic_statistics():
    cache = InMemoryDNSCache()
    assert isinstance(cache, DNSCacheProtocol)

    key = CacheKey("example.com")
    cache.get(key)
    cache.put(key, make_entry(key))
    cache.get(key)

    stats = cache.get_stats()
    assert stats.hits == 1
    assert stats.misses == 1
    assert stats.evictions == 0
    assert stats.size == 1
    assert stats.hit_ratio == 0.5
