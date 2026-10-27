"""
Cache-aware DNS resolution (Task 5.6).
"""

from typing import Optional
from idns.contracts.resolver import DNSResolverProtocol, ResolutionContext, ResolverResult
from idns.contracts.cache import DNSCacheProtocol, CacheKey, CacheEntry, compute_rfc2308_ttl
from idns.core.cname import CNAMEChainProcessor
from idns.model import CNAMERecord


class CacheAwareResolver(DNSResolverProtocol):
    """
    Wraps an iterative DNS resolver with cache-first lookup logic.
    Handles CNAME aliasing seamlessly.
    """

    def __init__(
        self,
        cache: DNSCacheProtocol,
        iterative_resolver: DNSResolverProtocol,
    ) -> None:
        self.cache = cache
        self.iterative_resolver = iterative_resolver
        self.cname_processor = CNAMEChainProcessor(self.resolve)
        set_prefetch_callback = getattr(cache, "set_prefetch_callback", None)
        if callable(set_prefetch_callback):
            set_prefetch_callback(self._prefetch)

    def resolve(
        self,
        domain_name: str,
        record_type: str = "A",
        context: Optional[ResolutionContext] = None,
    ) -> ResolverResult:
        context = context or ResolutionContext()
        key = CacheKey.from_query(domain_name, record_type)

        # 1. Lookup in Cache
        entry = self.cache.get(key)
        
        # Cross-qtype logic for NXDOMAIN: if A record is NXDOMAIN, then AAAA is also NXDOMAIN
        # The cache protocol specifies NXDOMAIN is name-level.
        if entry is None and record_type != "A":
            any_type_key = CacheKey.from_query(domain_name, "A")
            any_entry = self.cache.get(any_type_key)
            if any_entry and any_entry.is_nxdomain:
                entry = any_entry

        if entry is not None:
            # CACHE HIT
            context.trace_log.append(f"cache hit: {key.domain_name} {key.record_type}")
            result = ResolverResult(
                domain_name=domain_name,
                record_type=record_type,
                answers=list(entry.records),
                authoritative_servers=[entry.soa_record] if entry.soa_record else [],
                rcode=3 if entry.is_nxdomain else 0,
                is_nxdomain=entry.is_nxdomain,
                is_cache_hit=True,
                query_count=context.query_count,
                cname_chain=list(context.cname_chain),
                trace_log=list(context.trace_log),
                is_nodata=entry.is_negative and not entry.is_nxdomain,
            )
            # Process CNAMEs on cached results
            return self.cname_processor.process(domain_name, record_type, result, context)

        # 2. CACHE MISS -> Iterative Resolution
        context.trace_log.append(f"cache miss: {key.domain_name} {key.record_type}")
        result = self.iterative_resolver.resolve(domain_name, record_type, context)

        # 3. Cache the Result
        self._cache_result(key, result)

        # 4. Process CNAMEs on network result
        return self.cname_processor.process(domain_name, record_type, result, context)

    def _prefetch(self, key: CacheKey, _entry: CacheEntry) -> None:
        """Refresh one nearly expired entry without consulting the cache."""
        result = self.iterative_resolver.resolve(
            key.domain_name,
            key.record_type,
            ResolutionContext(),
        )
        self._cache_result(key, result)

    def _cache_result(self, key: CacheKey, result: ResolverResult) -> None:
        """Apply positive or RFC 2308 negative caching to a result."""
        is_nodata = getattr(result, "is_nodata", False) or (
            result.rcode == 0
            and not result.answers
            and any(
                getattr(record, "record_type", "") == "SOA"
                for record in result.authoritative_servers
            )
        )
        if result.is_nxdomain or is_nodata:
            # Negative Caching (NXDOMAIN or NODATA)
            soa = next((r for r in result.authoritative_servers if getattr(r, 'record_type', '') == 'SOA'), None)
            put_negative = getattr(self.cache, "put_negative", None)
            if callable(put_negative):
                # Let the concrete cache apply its configured negative-TTL
                # policy instead of rebuilding an entry with the default
                # 300-second limit here.
                put_negative(
                    key,
                    is_nxdomain=result.is_nxdomain,
                    soa_record=soa,
                )
            else:
                # Retain compatibility with third-party/cache test doubles
                # implementing only DNSCacheProtocol.
                ttl = compute_rfc2308_ttl(soa)
                neg_entry = CacheEntry.create_negative(
                    key=key,
                    is_nxdomain=result.is_nxdomain,
                    ttl_seconds=ttl,
                    soa_record=soa,
                )
                self.cache.put(key, neg_entry)
        
        elif result.rcode == 0 and result.answers:
            # Positive Caching
            self._cache_positive_result(key, result)

    def _cache_positive_result(self, key: CacheKey, result: ResolverResult) -> None:
        """Cache positive RRsets without combining unrelated owner names.

        A response containing a CNAME and its in-message target can contain
        multiple independently expiring RRsets.  Keep the alias CNAME under
        the original query key and index each reachable target separately so
        later queries can use those RRsets without another iterative lookup.
        """
        cname_records = [
            record for record in result.answers if isinstance(record, CNAMERecord)
        ]
        if not cname_records:
            self._put_positive(key, result.answers)
            return

        records_by_name: dict[str, list[object]] = {}
        for record in result.answers:
            name = getattr(getattr(record, "name", None), "value", "").lower().rstrip(".")
            if name:
                records_by_name.setdefault(name, []).append(record)

        # Follow only CNAME targets reachable from the queried owner.  This
        # avoids caching unrelated answer/additional records from the packet.
        current_name = key.domain_name
        visited: set[str] = set()
        while current_name not in visited:
            visited.add(current_name)
            owner_records = records_by_name.get(current_name, [])
            cname_rrset = [record for record in owner_records if isinstance(record, CNAMERecord)]
            if cname_rrset:
                self._put_positive(key.__class__(current_name, key.record_type, key.dns_class), cname_rrset)
                current_name = cname_rrset[0].canonical_name.value.lower().rstrip(".")
                continue

            target_rrset = [
                record for record in owner_records
                if getattr(record, "record_type", "").upper() == key.record_type
            ]
            if target_rrset:
                self._put_positive(key.__class__(current_name, key.record_type, key.dns_class), target_rrset)
            break

    def _put_positive(self, key: CacheKey, records: list[object]) -> None:
        """Store one RRset using the lowest TTL in that RRset."""
        if not records:
            return
        min_ttl = min(getattr(record, "ttl", 300) for record in records)
        self.cache.put(
            key,
            CacheEntry.create_positive(key, records, min_ttl),
        )
