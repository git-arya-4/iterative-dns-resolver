"""
Contracts package defining stable protocol interfaces and data abstractions across team modules.

Exported Contracts & Types:
- Codec: DNSCodecProtocol
- Transport: DNSTransportProtocol, ServerAddress, TransportConfig, TransportResult
- Cache: DNSCacheProtocol, CacheKey, CacheEntry, CacheStats
- Resolver: DNSResolverProtocol, ResolutionContext, ResolverResult
"""

from idns.contracts.codec import DNSCodecProtocol
from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.contracts.cache import (
    DNSCacheProtocol,
    CacheKey,
    CacheEntry,
    CacheStats,
    CacheConfig,
    compute_rfc2308_ttl,
)
from idns.contracts.resolver import (
    DNSResolverProtocol,
    ResolutionContext,
    ResolverResult,
)

__all__ = [
    "DNSCodecProtocol",
    "DNSTransportProtocol",
    "ServerAddress",
    "TransportConfig",
    "TransportResult",
    "DNSCacheProtocol",
    "CacheKey",
    "CacheEntry",
    "CacheStats",
    "CacheConfig",
    "compute_rfc2308_ttl",
    "DNSResolverProtocol",
    "ResolutionContext",
    "ResolverResult",
]
