"""In-memory positive and negative DNS cache."""

from dataclasses import replace
import time
from typing import Any, Callable, Optional

from idns.contracts.cache import (
    CacheConfig,
    CacheEntry,
    CacheKey,
    CacheStats,
    DNSCacheProtocol,
    compute_rfc2308_ttl,
)

_NXDOMAIN_RECORD_TYPE = "__NXDOMAIN__"


class InMemoryDNSCache(DNSCacheProtocol):
    """DNS cache with lazy TTL expiration and RFC 2308 negative entries."""

    def __init__(
        self,
        config: Optional[CacheConfig] = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config or CacheConfig()
        self._clock = clock
        self._entries: dict[CacheKey, CacheEntry] = {}
        self._stats = CacheStats()

    def get(
        self,
        key: CacheKey,
        current_timestamp: Optional[float] = None,
    ) -> Optional[CacheEntry]:
        """Return an unexpired entry, removing expired entries on lookup."""
        if not self._config.enabled:
            self._stats.misses += 1
            return None

        canonical_key = key.canonical()
        entry_key = canonical_key
        entry = self._entries.get(entry_key)
        if entry is None:
            entry_key = self._nxdomain_key(canonical_key)
            entry = self._entries.get(entry_key)
        now = self._clock() if current_timestamp is None else current_timestamp
        if entry is None:
            self._stats.misses += 1
            return None
        if entry.is_expired(now):
            del self._entries[entry_key]
            self._stats.misses += 1
            self._stats.evictions += 1
            self._stats.size = len(self._entries)
            return None

        self._stats.hits += 1
        return entry

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        """Store an entry under its canonical key."""
        if not self._config.enabled:
            return

        canonical_key = key.canonical()
        if entry.key != canonical_key:
            entry = replace(entry, key=canonical_key)
        if self._config.max_entries <= 0:
            return
        if canonical_key not in self._entries:
            self._enforce_capacity()
        self._entries[canonical_key] = entry
        self._stats.size = len(self._entries)

    def _enforce_capacity(self) -> None:
        """Evict the entry with the earliest expiration at configured capacity."""
        if len(self._entries) < self._config.max_entries:
            return

        key_to_evict = min(
            self._entries,
            key=lambda key: (
                self._entries[key].creation_timestamp + self._entries[key].ttl_seconds,
                key.domain_name,
                key.record_type,
                key.dns_class,
            ),
        )
        del self._entries[key_to_evict]
        self._stats.evictions += 1

    def put_positive(self, key: CacheKey, records: list[Any]) -> None:
        """Store a positive RRset using its lowest record TTL."""
        if not records:
            raise ValueError("Positive cache entries require at least one record")

        try:
            ttl_seconds = min(record.ttl for record in records)
        except AttributeError as error:
            raise ValueError("Positive cache records must provide a ttl") from error

        entry = CacheEntry.create_positive(
            key,
            records,
            ttl_seconds,
            creation_timestamp=self._clock(),
        )
        self.put(key, entry)

    def put_negative(
        self,
        key: CacheKey,
        *,
        is_nxdomain: bool,
        soa_record: Optional[Any] = None,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store an RFC 2308 NXDOMAIN or NODATA cache entry."""
        if not self._config.rfc2308_enabled:
            return

        effective_ttl = (
            compute_rfc2308_ttl(soa_record, self._config.negative_ttl_seconds)
            if ttl_seconds is None
            else max(0, ttl_seconds)
        )
        storage_key = self._nxdomain_key(key) if is_nxdomain else key
        entry = CacheEntry.create_negative(
            storage_key,
            is_nxdomain,
            effective_ttl,
            soa_record=soa_record,
            creation_timestamp=self._clock(),
        )
        self.put(storage_key, entry)

    @staticmethod
    def _nxdomain_key(key: CacheKey) -> CacheKey:
        """Return the type-independent key used for an NXDOMAIN response."""
        canonical_key = key.canonical()
        return CacheKey(
            canonical_key.domain_name,
            _NXDOMAIN_RECORD_TYPE,
            canonical_key.dns_class,
        )

    def remove(self, key: CacheKey) -> bool:
        canonical_key = key.canonical()
        if canonical_key not in self._entries:
            return False
        del self._entries[canonical_key]
        self._stats.evictions += 1
        self._stats.size = len(self._entries)
        return True

    def clear(self) -> None:
        self._entries.clear()
        self._stats.size = 0

    def get_stats(self) -> CacheStats:
        return self._stats


class TTLCache(InMemoryDNSCache):
    """Backward-compatible name for the TTL-aware in-memory cache."""


__all__ = ["InMemoryDNSCache", "TTLCache"]
