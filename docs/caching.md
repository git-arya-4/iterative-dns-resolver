# DNS Cache Subsystem

**Status:** Implemented positive and negative TTL caching
**Owners:** Swastik (cache implementation) and Arya (shared contracts)

## Purpose

The cache reduces repeated DNS queries, honors record TTLs, supports RFC 2308
negative caching, and exposes metrics for later experiments. `InMemoryDNSCache`
provides the TTL, RFC 2308, and cache-aware resolver behavior used by the
production resolver.

## API (`idns.contracts.cache`)

- `CacheKey(domain_name, record_type="A", dns_class="IN")` identifies an
  RRset. `canonical()` and `from_query()` normalize domain case, trailing dots,
  record type, and class.
- `CacheConfig` contains `enabled`, `max_entries`,
  `negative_ttl_seconds`, and `rfc2308_enabled`. The configured negative TTL
  is an upper bound for both NXDOMAIN and NODATA entries.
- `CacheEntry` stores records or a negative result. Use
  `create_positive()` for answers and `create_negative()` for NXDOMAIN or
  NODATA. `is_expired()` and `remaining_ttl()` apply TTL behavior.
- `compute_rfc2308_ttl(soa_record, max_negative_ttl=300)` returns the lower of
  the SOA TTL and SOA MINIMUM, capped by the configured maximum. Without an
  SOA, it returns the configured maximum.
- `CacheStats` tracks hits, misses, evictions, size, and hit ratio.
- `DNSCacheProtocol` requires `get`, `put`, `remove`, `clear`, and
  `get_stats`. `TTLCache` in `idns.cache` is the initial implementation.

## Implemented behavior

- `put_positive()` caches a positive RRset using its lowest record TTL.
- `put_negative()` caches NXDOMAIN or NODATA entries. With an SOA record it
  uses `min(SOA TTL, SOA MINIMUM, negative_ttl_seconds)`; without one it uses
  the configured fallback TTL. Explicit TTL overrides are capped by the same
  policy.
- `get()` lazily removes expired positive and negative entries, recording a
  cache miss and eviction.
- When capacity is reached, the cache evicts the entry with the earliest
  expiration time. Ties are broken by canonical key values for repeatable
  behavior.
- NXDOMAIN entries are indexed by domain name and class, so one cached name
  error applies to every queried record type. NODATA entries remain
  record-type-specific.

## Resolver integration

- Cache positive RRsets using the lowest TTL in the set.
- Cache CNAMEs under the alias/type key and the target separately.
- Distinguish NXDOMAIN (`is_nxdomain=True`) from NODATA (`is_nodata=True`).
- Remove expired entries on lookup and apply a deterministic capacity policy.
- `TTLCache.get()` accepts an optional timestamp so expiration is deterministic
  in tests; normal callers use the current clock.

The cache-aware resolver delegates negative-entry creation to the cache so a
custom `CacheConfig` is honoured. Empty non-authoritative referrals are not
classified as NODATA and are not cached as negative answers.

## Near-expiry prefetching

Set `CacheConfig(prefetch_enabled=True)` to refresh a valid entry when its
remaining TTL is at or below `prefetch_threshold_seconds` (30 seconds by
default). The refresh uses the iterative resolver and stores the new RRset;
an upstream failure is ignored while the old entry remains valid. Prefetching
is disabled by default so applications can opt into the additional traffic.
