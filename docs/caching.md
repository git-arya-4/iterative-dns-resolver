# DNS Cache Subsystem

**Task:** 1.6 - Define the cache API with Swastik
**Owners:** Swastik (cache implementation) and Arya (shared contracts)

## Purpose

The cache will reduce repeated DNS queries, honor record TTLs, support RFC 2308
negative caching, and expose metrics for later experiments. Task 1.6 defines
the shared interface; `TTLCache` provides the Task 3.10 TTL storage behavior.

## API (`idns.contracts.cache`)

- `CacheKey(domain_name, record_type="A", dns_class="IN")` identifies an
  RRset. `canonical()` and `from_query()` normalize domain case, trailing dots,
  record type, and class.
- `CacheConfig` contains `enabled`, `max_entries`,
  `negative_ttl_seconds`, and `rfc2308_enabled`.
- `CacheEntry` stores records or a negative result. Use
  `create_positive()` for answers and `create_negative()` for NXDOMAIN or
  NODATA. `is_expired()` and `remaining_ttl()` apply TTL behavior.
- `compute_rfc2308_ttl(soa_record, max_negative_ttl=300)` returns the lower of
  the SOA TTL and SOA MINIMUM, capped by the configured maximum. Without an
  SOA, it returns the configured maximum.
- `CacheStats` tracks hits, misses, evictions, size, and hit ratio.
- `DNSCacheProtocol` requires `get`, `put`, `remove`, `clear`, and
  `get_stats`. `TTLCache` in `idns.cache` is the initial implementation.

## Required behavior for later implementation

- Cache positive RRsets using the lowest TTL in the set.
- Cache CNAMEs under the alias/type key and the target separately.
- Distinguish NXDOMAIN (`is_nxdomain=True`) from NODATA (`False`).
- Remove expired entries on lookup and apply a deterministic capacity policy.
- `TTLCache.get()` accepts an optional timestamp so expiration is deterministic
  in tests; normal callers use the current clock.

## Follow-up tasks

- **2.7:** cache store/get/put skeleton.
- **3.10:** TTL storage and expiration (`TTLCache`).
- **5.1-5.3:** positive and negative cache integration with the resolver.
