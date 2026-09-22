"""
DNS Cache Subsystem Contract.

Owner: Shared Contract (Defined by Arya & Swastik, implemented by Swastik in src/idns/cache)
Phase: Phase 1 (Contract Definition - Task 1.6) / Phase 2 & 5 (Implementation)

Defines cache abstractions supporting positive entry storage, TTL-based eviction,
and RFC 2308 negative caching (NXDOMAIN / NODATA).
"""

from dataclasses import dataclass, field
import time
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class CacheKey:
    """
    Unique key for DNS cache record lookups.
    
    Supports string domain names or DNSName instances.
    """
    domain_name: Any
    record_type: str = "A"
    dns_class: str = "IN"

    def canonical(self) -> "CacheKey":
        """
        Return canonicalized key:
        - Domain name converted to string, trimmed, lowercased, and trailing dot stripped.
        - Record type and class normalized to uppercase.
        """
        domain_str = str(self.domain_name).strip().lower().rstrip(".")
        return CacheKey(
            domain_name=domain_str,
            record_type=self.record_type.strip().upper(),
            dns_class=self.dns_class.strip().upper(),
        )

    @classmethod
    def from_query(cls, domain: Any, record_type: str = "A", dns_class: str = "IN") -> "CacheKey":
        """Convenience constructor to create a canonical CacheKey directly from a query."""
        return cls(domain_name=domain, record_type=record_type, dns_class=dns_class).canonical()


@dataclass
class CacheConfig:
    """
    Configuration parameters for the DNS cache subsystem.
    
    Matches settings defined in config/resolver.toml [cache] section.
    """
    enabled: bool = True
    max_entries: int = 10000
    negative_ttl_seconds: int = 300
    rfc2308_enabled: bool = True


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
    creation_timestamp: float = field(default_factory=time.time)
    is_negative: bool = False
    is_nxdomain: bool = False  # True for NXDOMAIN, False for NODATA if is_negative=True
    soa_record: Optional[Any] = None

    def is_expired(self, current_timestamp: Optional[float] = None) -> bool:
        """
        Check if entry TTL has expired relative to creation timestamp.
        If current_timestamp is omitted, time.time() is used.
        """
        ts = current_timestamp if current_timestamp is not None else time.time()
        return (ts - self.creation_timestamp) >= self.ttl_seconds

    def remaining_ttl(self, current_timestamp: Optional[float] = None) -> int:
        """
        Calculate remaining TTL in seconds.
        If current_timestamp is omitted, time.time() is used.
        """
        ts = current_timestamp if current_timestamp is not None else time.time()
        remaining = self.ttl_seconds - int(ts - self.creation_timestamp)
        return max(0, remaining)

    @classmethod
    def create_positive(
        cls,
        key: CacheKey,
        records: list[Any],
        ttl_seconds: int,
        creation_timestamp: Optional[float] = None,
    ) -> "CacheEntry":
        """Factory constructor for positive response cache entries."""
        ts = creation_timestamp if creation_timestamp is not None else time.time()
        return cls(
            key=key.canonical(),
            records=records,
            ttl_seconds=max(0, ttl_seconds),
            creation_timestamp=ts,
            is_negative=False,
            is_nxdomain=False,
            soa_record=None,
        )

    @classmethod
    def create_negative(
        cls,
        key: CacheKey,
        is_nxdomain: bool,
        ttl_seconds: int,
        soa_record: Optional[Any] = None,
        creation_timestamp: Optional[float] = None,
    ) -> "CacheEntry":
        """
        Factory constructor for RFC 2308 negative response cache entries (NXDOMAIN or NODATA).
        """
        ts = creation_timestamp if creation_timestamp is not None else time.time()
        return cls(
            key=key.canonical(),
            records=[],
            ttl_seconds=max(0, ttl_seconds),
            creation_timestamp=ts,
            is_negative=True,
            is_nxdomain=is_nxdomain,
            soa_record=soa_record,
        )


def compute_rfc2308_ttl(soa_record: Optional[Any], max_negative_ttl: int = 300) -> int:
    """
    Compute negative caching TTL from an authority SOA record under RFC 2308 Section 3/5.
    
    RFC 2308 specifies that the negative response TTL is taken from:
        min(SOA.ttl, SOA.minimum)
    
    If the SOA record is missing or attributes are unavailable, max_negative_ttl is returned.
    The resulting TTL is bounded above by max_negative_ttl and bounded below by 0.
    """
    if soa_record is None:
        return max(0, max_negative_ttl)

    soa_ttl = getattr(soa_record, "ttl", None)
    soa_minimum = getattr(soa_record, "minimum", None)

    candidates = [max_negative_ttl]
    if isinstance(soa_ttl, (int, float)):
        candidates.append(int(soa_ttl))
    if isinstance(soa_minimum, (int, float)):
        candidates.append(int(soa_minimum))

    return max(0, min(candidates))


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
    Protocol defining the contract for the DNS caching engine.
    
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
