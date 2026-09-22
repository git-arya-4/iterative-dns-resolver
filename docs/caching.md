# DNS Cache Subsystem Specification & API Reference

**Subsystem**: DNS Cache Engine (`idns.cache`)  
**Task**: Sub-task 1.6 — Define Cache API with Swastik  
**Owners**: Swastik (Implementation Owner) & Arya (Contracts & Systems Integrator)  
**Status**: Stable API Contract Defined (Phase 1 Gate Passed)

---

## 1. Overview & Purpose

The DNS Cache subsystem provides an in-memory, thread-safe, TTL-aware caching layer designed to:
1. Drastically reduce outbound network queries to root, TLD, and authoritative nameservers.
2. Comply with standard DNS TTL semantics for positive responses.
3. Fully adhere to **RFC 2308** for negative caching (both `NXDOMAIN` and `NODATA` responses).
4. Supply real-time cache metrics (`hits`, `misses`, `evictions`, `hit_ratio`) for performance benchmarking and experiments (Phase 8).

---

## 2. Stable Cache API Contract (`idns.contracts.cache`)

The cache interface is defined in `idns.contracts.cache` and exported via `idns.contracts`.

### 2.1. `CacheKey`
Represents the unique lookup key for a cached resource record set.

```python
@dataclass(frozen=True)
class CacheKey:
    domain_name: Any       # str or DNSName
    record_type: str = "A" # "A", "AAAA", "NS", "CNAME", "MX", "TXT", "SOA"
    dns_class: str = "IN"

    def canonical(self) -> "CacheKey":
        """Returns a canonicalized key: trimmed, lowercased domain, stripped trailing dot, uppercase type/class."""
        ...

    @classmethod
    def from_query(cls, domain: Any, record_type: str = "A", dns_class: str = "IN") -> "CacheKey":
        """Direct constructor from query parameters returning a canonical key."""
        ...
```

**Key Invariants**:
- Case-insensitive lookups: `"EXAMPLE.COM"` and `"example.com."` resolve to the same canonical key.
- Accepts both raw `str` and `idns.model.DNSName` objects.

---

### 2.2. `CacheConfig`
Encapsulates runtime configuration loaded from `config/resolver.toml`:

```python
@dataclass
class CacheConfig:
    enabled: bool = True
    max_entries: int = 10000
    negative_ttl_seconds: int = 300
    rfc2308_enabled: bool = True
```

---

### 2.3. `CacheEntry`
Encapsulates stored DNS responses (positive and negative):

```python
@dataclass
class CacheEntry:
    key: CacheKey
    records: list[Any] = field(default_factory=list) # List of ResourceRecord models
    ttl_seconds: int = 300
    creation_timestamp: float = field(default_factory=time.time)
    is_negative: bool = False
    is_nxdomain: bool = False  # True: NXDOMAIN, False: NODATA
    soa_record: Optional[Any] = None

    def is_expired(self, current_timestamp: Optional[float] = None) -> bool:
        """Evaluates whether (current_time - creation_timestamp) >= ttl_seconds."""
        ...

    def remaining_ttl(self, current_timestamp: Optional[float] = None) -> int:
        """Returns remaining seconds before expiration, bounded below by 0."""
        ...

    @classmethod
    def create_positive(cls, key: CacheKey, records: list[Any], ttl_seconds: int, ...) -> "CacheEntry":
        ...

    @classmethod
    def create_negative(cls, key: CacheKey, is_nxdomain: bool, ttl_seconds: int, soa_record: Optional[Any] = None, ...) -> "CacheEntry":
        ...
```

---

### 2.4. `compute_rfc2308_ttl`
Utility function computing negative TTL according to RFC 2308 Section 3/5:

```python
def compute_rfc2308_ttl(soa_record: Optional[Any], max_negative_ttl: int = 300) -> int:
    """
    Computes negative TTL as min(SOA.ttl, SOA.minimum), clamped by max_negative_ttl.
    Falls back to max_negative_ttl if SOA is absent.
    """
```

---

### 2.5. `CacheStats`
Metrics container for cache telemetry:

```python
@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0

    @property
    def hit_ratio(self) -> float:
        ...
```

---

### 2.6. `DNSCacheProtocol`
The formal interface contract implemented by `idns.cache`:

```python
@runtime_checkable
class DNSCacheProtocol(Protocol):
    def get(self, key: CacheKey) -> Optional[CacheEntry]:
        """Lookup an unexpired entry. Returns None on miss or expired entry."""
        ...

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        """Store or update a cache entry."""
        ...

    def remove(self, key: CacheKey) -> bool:
        """Evict a specific entry by key. Returns True if removed."""
        ...

    def clear(self) -> None:
        """Purge all entries and reset size."""
        ...

    def get_stats(self) -> CacheStats:
        """Return current performance telemetry."""
        ...
```

---

## 3. Caching Semantics & Operational Rules

### 3.1. Positive Response Caching
1. **RRset TTL**: When an answer contains multiple records for the same RRset, the cached TTL is set to the minimum TTL among the records in that RRset.
2. **On-Read TTL Adjustment**: Upon returning cached records to the resolver or client, the TTL on outgoing records may be adjusted to `entry.remaining_ttl()`.
3. **CNAME Caching**: CNAME records are cached under their own `(alias, "CNAME")` key; resolution of the target domain is cached separately under its own target key.

### 3.2. Negative Caching (RFC 2308)
1. **NXDOMAIN (Name Error, RCODE=3)**:
   - Indicates the domain name does not exist.
   - Cached with `is_negative=True, is_nxdomain=True`.
   - TTL is computed from the authority section SOA record using `compute_rfc2308_ttl(soa)`.
2. **NODATA (No Error, RCODE=0, ANCOUNT=0)**:
   - Indicates the domain name exists, but has no records of the requested type.
   - Cached with `is_negative=True, is_nxdomain=False`.
   - TTL is computed from the authority section SOA record using `compute_rfc2308_ttl(soa)`.

### 3.3. Eviction Policies
- **Lazy Expiration**: On `get()`, if `entry.is_expired()`, the entry is evicted and treated as a cache miss.
- **Capacity Eviction (LRU)**: When `len(cache) >= max_entries`, the least recently used or earliest expiring entry is evicted to respect the memory budget.

---

## 4. Integration Gates & Next Steps
- **Gate 1 (Foundation)**: Sub-task 1.6 complete.
- **Phase 2 (Task 2.7)**: Swastik implements `CacheStore` skeleton under `src/idns/cache/`.
- **Phase 3 (Task 3.10)**: Swastik implements TTL storage and expiration calculation.
- **Phase 5 (Tasks 5.1 - 5.3)**: Swastik completes full positive/negative caching engine and integrates with Arya's `CoreResolver`.
