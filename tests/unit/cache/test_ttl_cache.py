from idns.cache import TTLCache
from idns.contracts.cache import CacheEntry, CacheKey


def test_put_and_get_returns_unexpired_entry_with_remaining_ttl():
    cache = TTLCache()
    key = CacheKey("EXAMPLE.COM.", "a")
    entry = CacheEntry.create_positive(key, ["answer"], 60, creation_timestamp=100.0)

    cache.put(key, entry)

    result = cache.get(CacheKey("example.com", "A"), current_timestamp=125.0)
    assert result is not None
    assert result.records == ["answer"]
    assert result.remaining_ttl(125.0) == 35


def test_get_expires_entry_and_records_miss():
    cache = TTLCache()
    key = CacheKey("example.com")
    cache.put(key, CacheEntry.create_positive(key, ["answer"], 10, creation_timestamp=100.0))

    assert cache.get(key, current_timestamp=110.0) is None
    stats = cache.get_stats()
    assert stats.hits == 0
    assert stats.misses == 1
    assert stats.evictions == 1
    assert stats.size == 0


def test_put_replaces_entry_and_clear_resets_storage():
    cache = TTLCache()
    key = CacheKey("example.com")
    cache.put(key, CacheEntry.create_positive(key, ["old"], 60, creation_timestamp=100.0))
    cache.put(key, CacheEntry.create_positive(key, ["new"], 60, creation_timestamp=100.0))
    assert cache.get(key, current_timestamp=101.0).records == ["new"]

    cache.clear()
    assert cache.get(key, current_timestamp=101.0) is None
