"""
DNS Cache Subsystem Contract.

Owner: Shared Contract (Implemented by Swastik in src/idns/cache)
Phase: Phase 0 (Contract) / Phase 5 (Implementation)

Defines cache abstractions supporting positive entry storage, TTL-based eviction,
and RFC 2308 negative caching (NXDOMAIN / NODATA).
"""

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class CacheKey:
    """Unique key for cache record lookups."""
    domain_name: str
    record_type: str = "A"
    dns_class: str = "IN"

    def canonical(self) -> "CacheKey":
        """Return canonicalized key (lowercased domain name)."""
        return CacheKey(
            domain_name=self.domain_name.strip().lower().rstrip("."),
            record_type=self.record_type.upper(),
            dns_class=self.dns_class.upper(),
        )


@dataclass
class CacheEntry:
    """
    Represents a cached DNS response entry.
    
    Supports both positive caching (list of resource records) and
    RFC 2308 negative caching (is_negative=True, nxdomain/nodata flag).
    """
    key: CacheKey
    records: list[Any] = field(default_factory=list)
    ttl_seconds: int = 300
    creation_timestamp: float = 0.0
    is_negative: bool = False
    is_nxdomain: bool = False  # True for NXDOMAIN, False for NODATA if is_negative=True
    soa_record: Optional[Any] = None

    def is_expired(self, current_timestamp: float) -> bool:
        """Check if entry TTL has expired relative to creation timestamp."""
        return (current_timestamp - self.creation_timestamp) >= self.ttl_seconds

    def remaining_ttl(self, current_timestamp: float) -> int:
        """Calculate remaining TTL in seconds."""
        remaining = self.ttl_seconds - int(current_timestamp - self.creation_timestamp)
        return max(0, remaining)


@dataclass
class CacheStats:
    """Metrics container for cache performance analysis."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total > 0 else 0.0


@runtime_checkable
class DNSCacheProtocol(Protocol):
    """
    Protocol defining the contract for DNS caching engine.
    
    Swastik's cache module (`src/idns/cache`) must satisfy this protocol.
    """

    def get(self, key: CacheKey) -> Optional[CacheEntry]:
        """
        Retrieve a valid unexpired positive or negative cache entry.
        
        Args:
            key: Target domain, record type, and class.
            
        Returns:
            CacheEntry if hit and unexpired, None on miss or expired entry.
        """
        ...

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        """
        Store a positive or negative cache entry with TTL.
        
        Args:
            key: Target lookup key.
            entry: Entry containing records or negative RFC 2308 indicators.
        """
        ...

    def remove(self, key: CacheKey) -> bool:
        """
        Manually evict a key from the cache.
        
        Returns:
            bool: True if entry existed and was removed, False otherwise.
        """
        ...

    def clear(self) -> None:
        """Purge all entries from the cache."""
        ...

    def get_stats(self) -> CacheStats:
        """Return cache hit/miss and eviction metrics."""
        ...
