"""Basic in-memory DNS cache implementation.

This module intentionally provides only the storage skeleton required by
``DNSCacheProtocol``.  Expiration, negative-cache policy, eviction policy,
and persistence belong to later tasks.
"""

from idns.contracts.cache import (
    CacheEntry,
    CacheKey,
    CacheStats,
    DNSCacheProtocol,
)


class InMemoryDNSCache(DNSCacheProtocol):
    """Store cache entries in memory, indexed by canonical cache keys."""

    def __init__(self) -> None:
        self._entries: dict[CacheKey, CacheEntry] = {}
        self._stats = CacheStats()

    def get(self, key: CacheKey) -> CacheEntry | None:
        """Return the entry for ``key`` and update hit/miss statistics."""

        entry = self._entries.get(key.canonical())
        if entry is None:
            self._stats.misses += 1
        else:
            self._stats.hits += 1
        return entry

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        """Store or replace an entry under the canonical form of ``key``."""

        self._entries[key.canonical()] = entry
        self._stats.size = len(self._entries)

    def remove(self, key: CacheKey) -> bool:
        """Remove ``key`` if present and report whether removal occurred."""

        canonical_key = key.canonical()
        if canonical_key not in self._entries:
            return False

        del self._entries[canonical_key]
        self._stats.evictions += 1
        self._stats.size = len(self._entries)
        return True

    def clear(self) -> None:
        """Remove all stored entries while preserving cumulative statistics."""

        self._entries.clear()
        self._stats.size = 0

    def get_stats(self) -> CacheStats:
        """Return the cache statistics required by the current contract."""

        return self._stats


__all__ = ["InMemoryDNSCache"]
