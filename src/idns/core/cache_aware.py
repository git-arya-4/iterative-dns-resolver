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
            )
            # Process CNAMEs on cached results
            return self.cname_processor.process(domain_name, record_type, result, context)

        # 2. CACHE MISS -> Iterative Resolution
        result = self.iterative_resolver.resolve(domain_name, record_type, context)

        # 3. Cache the Result
        if result.is_nxdomain or (result.rcode == 0 and not result.answers):
            # Negative Caching (NXDOMAIN or NODATA)
            soa = next((r for r in result.authoritative_servers if getattr(r, 'record_type', '') == 'SOA'), None)
            ttl = compute_rfc2308_ttl(soa)
            
            neg_entry = CacheEntry.create_negative(
                key=key,
                is_nxdomain=result.is_nxdomain,
                ttl_seconds=ttl,
                soa_record=soa,
            )
            
            # Store NODATA as qtype-specific, but NXDOMAIN as name-level (we store it under A by convention, or the requested type)
            # The prompt requires: "NXDOMAIN remains name-level... NODATA remains qtype-specific"
            # Since CacheKey includes record_type, we store NXDOMAIN on the requested type and rely on cross-qtype lookup,
            # or we store NXDOMAIN on all common types. The contract says NXDOMAIN is name level.
            # Storing under the requested key is safest, the cross-lookup handles A record lookup.
            # Actually, to make NXDOMAIN name-level, let's store it under "ANY" or just under the requested key, 
            # and if another qtype is asked, we check if NXDOMAIN exists for that name. We did that above using type A.
            # Let's store NXDOMAIN under type A as well to ensure it's found by the cross-qtype logic.
            self.cache.put(key, neg_entry)
            if result.is_nxdomain and record_type != "A":
                self.cache.put(CacheKey.from_query(domain_name, "A"), neg_entry)
        
        elif result.rcode == 0 and result.answers:
            # Positive Caching
            # Determine minimum TTL among answers
            ttls = [getattr(r, 'ttl', 300) for r in result.answers if hasattr(r, 'ttl')]
            min_ttl = min(ttls) if ttls else 300
            
            pos_entry = CacheEntry.create_positive(
                key=key,
                records=result.answers,
                ttl_seconds=min_ttl,
            )
            self.cache.put(key, pos_entry)

        # 4. Process CNAMEs on network result
        return self.cname_processor.process(domain_name, record_type, result, context)
