"""Stable cache API contract for Task 1.6."""
from dataclasses import dataclass, field
import time
from typing import Any, Optional, Protocol, runtime_checkable

@dataclass(frozen=True)
class CacheKey:
    domain_name: Any
    record_type: str = "A"
    dns_class: str = "IN"
    def canonical(self) -> "CacheKey":
        return CacheKey(str(self.domain_name).strip().lower().rstrip("."), self.record_type.strip().upper(), self.dns_class.strip().upper())
    @classmethod
    def from_query(cls, domain: Any, record_type: str = "A", dns_class: str = "IN") -> "CacheKey":
        return cls(domain, record_type, dns_class).canonical()

@dataclass
class CacheConfig:
    enabled: bool = True
    max_entries: int = 10000
    negative_ttl_seconds: int = 300
    rfc2308_enabled: bool = True

@dataclass
class CacheEntry:
    key: CacheKey
    records: list[Any] = field(default_factory=list)
    ttl_seconds: int = 300
    creation_timestamp: float = field(default_factory=time.time)
    is_negative: bool = False
    is_nxdomain: bool = False
    soa_record: Optional[Any] = None
    def is_expired(self, current_timestamp: Optional[float] = None) -> bool:
        now = time.time() if current_timestamp is None else current_timestamp
        return now - self.creation_timestamp >= self.ttl_seconds
    def remaining_ttl(self, current_timestamp: Optional[float] = None) -> int:
        now = time.time() if current_timestamp is None else current_timestamp
        return max(0, self.ttl_seconds - int(now - self.creation_timestamp))
    @classmethod
    def create_positive(cls, key: CacheKey, records: list[Any], ttl_seconds: int, creation_timestamp: Optional[float] = None) -> "CacheEntry":
        return cls(key.canonical(), records, max(0, ttl_seconds), time.time() if creation_timestamp is None else creation_timestamp)
    @classmethod
    def create_negative(cls, key: CacheKey, is_nxdomain: bool, ttl_seconds: int, soa_record: Optional[Any] = None, creation_timestamp: Optional[float] = None) -> "CacheEntry":
        return cls(key.canonical(), [], max(0, ttl_seconds), time.time() if creation_timestamp is None else creation_timestamp, True, is_nxdomain, soa_record)

def compute_rfc2308_ttl(soa_record: Optional[Any], max_negative_ttl: int = 300) -> int:
    """Compute negative TTL as min(SOA TTL, SOA MINIMUM), capped by policy."""
    limit = max(0, max_negative_ttl)
    if soa_record is None:
        return limit
    values = [limit]
    for attribute in ("ttl", "minimum"):
        value = getattr(soa_record, attribute, None)
        if isinstance(value, (int, float)):
            values.append(int(value))
    return max(0, min(values))

@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

@runtime_checkable
class DNSCacheProtocol(Protocol):
    def get(self, key: CacheKey) -> Optional[CacheEntry]: ...
    def put(self, key: CacheKey, entry: CacheEntry) -> None: ...
    def remove(self, key: CacheKey) -> bool: ...
    def clear(self) -> None: ...
    def get_stats(self) -> CacheStats: ...
