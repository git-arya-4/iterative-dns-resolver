<<<<<<< HEAD
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
=======
"""In-memory DNS cache implementation."""

from dataclasses import replace
import time
from typing import Optional

from idns.contracts.cache import CacheEntry, CacheKey, CacheStats


class TTLCache:
    """Store DNS entries and lazily remove them after their TTL expires."""
>>>>>>> 394714a (Task 3.10 TTL Storage)

    def __init__(self) -> None:
        self._entries: dict[CacheKey, CacheEntry] = {}
        self._stats = CacheStats()

<<<<<<< HEAD
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

=======
    def get(self, key: CacheKey, current_timestamp: Optional[float] = None) -> Optional[CacheEntry]:
        canonical_key = key.canonical()
        entry = self._entries.get(canonical_key)
        now = time.time() if current_timestamp is None else current_timestamp
        if entry is None:
            self._stats.misses += 1
            return None
        if entry.is_expired(now):
            del self._entries[canonical_key]
            self._stats.evictions += 1
            self._stats.misses += 1
            self._stats.size = len(self._entries)
            return None
        self._stats.hits += 1
        return entry

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        canonical_key = key.canonical()
        if entry.key != canonical_key:
            entry = replace(entry, key=canonical_key)
        self._entries[canonical_key] = entry
        self._stats.size = len(self._entries)

    def remove(self, key: CacheKey) -> bool:
        canonical_key = key.canonical()
        if canonical_key not in self._entries:
            return False
>>>>>>> 394714a (Task 3.10 TTL Storage)
        del self._entries[canonical_key]
        self._stats.evictions += 1
        self._stats.size = len(self._entries)
        return True

    def clear(self) -> None:
<<<<<<< HEAD
        """Remove all stored entries while preserving cumulative statistics."""

=======
>>>>>>> 394714a (Task 3.10 TTL Storage)
        self._entries.clear()
        self._stats.size = 0

    def get_stats(self) -> CacheStats:
<<<<<<< HEAD
        """Return the cache statistics required by the current contract."""

        return self._stats


__all__ = ["InMemoryDNSCache"]
=======
        return self._stats


__all__ = ["TTLCache"]
>>>>>>> 394714a (Task 3.10 TTL Storage)
