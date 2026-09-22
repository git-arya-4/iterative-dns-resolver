"""
Unit test verifying that contract protocols in idns.contracts can be satisfied by mock implementations.
"""

from typing import Any, Optional
import pytest

from idns.contracts import (
    DNSCodecProtocol,
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
    DNSCacheProtocol,
    CacheKey,
    CacheEntry,
    CacheStats,
    DNSResolverProtocol,
    ResolutionContext,
    ResolverResult,
)


class MockCodec:
    """Mock implementation of DNSCodecProtocol for unit test validation."""
    def encode(self, message: Any) -> bytes:
        return b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    def decode(self, packet: bytes) -> Any:
        return {"id": 1, "qr": 0}

    def validate_packet(self, packet: bytes) -> bool:
        return len(packet) >= 12


class MockTransport:
    """Mock implementation of DNSTransportProtocol for unit test validation."""
    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config: Optional[TransportConfig] = None,
    ) -> TransportResult:
        return TransportResult(
            raw_response=b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
            server_used=server,
            rtt_ms=12.5,
            tc_bit_set=False,
        )


class MockCache:
    """Mock implementation of DNSCacheProtocol for unit test validation."""
    def __init__(self):
        self._store: dict[CacheKey, CacheEntry] = {}
        self.stats = CacheStats()

    def get(self, key: CacheKey) -> Optional[CacheEntry]:
        canonical_key = key.canonical()
        if canonical_key in self._store:
            self.stats.hits += 1
            return self._store[canonical_key]
        self.stats.misses += 1
        return None

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        self._store[key.canonical()] = entry
        self.stats.size = len(self._store)

    def remove(self, key: CacheKey) -> bool:
        canonical_key = key.canonical()
        if canonical_key in self._store:
            del self._store[canonical_key]
            self.stats.evictions += 1
            self.stats.size = len(self._store)
            return True
        return False

    def clear(self) -> None:
        self._store.clear()
        self.stats.size = 0

    def get_stats(self) -> CacheStats:
        return self.stats


class MockResolver:
    """Mock implementation of DNSResolverProtocol for unit test validation."""
    def resolve(
        self,
        domain_name: str,
        record_type: str = "A",
        context: Optional[ResolutionContext] = None,
    ) -> ResolverResult:
        ctx = context or ResolutionContext()
        ctx.query_count += 1
        return ResolverResult(
            domain_name=domain_name,
            record_type=record_type,
            answers=["93.184.216.34"],
            rcode=0,
            query_count=ctx.query_count,
            total_rtt_ms=25.0,
        )


def test_codec_protocol():
    codec = MockCodec()
    assert isinstance(codec, DNSCodecProtocol)
    encoded = codec.encode({"test": True})
    assert len(encoded) == 12
    decoded = codec.decode(encoded)
    assert decoded["id"] == 1
    assert codec.validate_packet(encoded) is True


def test_transport_protocol():
    transport = MockTransport()
    assert isinstance(transport, DNSTransportProtocol)
    server = ServerAddress(ip="198.41.0.4", port=53)
    res = transport.send_query(server, b"test_query")
    assert res.rtt_ms == 12.5
    assert res.server_used.ip == "198.41.0.4"
    assert res.tc_bit_set is False


def test_cache_protocol():
    cache = MockCache()
    assert isinstance(cache, DNSCacheProtocol)
    
    key = CacheKey("EXAMPLE.COM", "A")
    assert key.canonical().domain_name == "example.com"
    
    entry = CacheEntry(key=key, records=["93.184.216.34"], ttl_seconds=300, creation_timestamp=100.0)
    cache.put(key, entry)
    
    hit = cache.get(CacheKey("example.com", "A"))
    assert hit is not None
    assert hit.records == ["93.184.216.34"]
    assert cache.get_stats().hits == 1

    miss = cache.get(CacheKey("other.com", "A"))
    assert miss is None
    assert cache.get_stats().misses == 1

    assert cache.remove(key) is True
    assert cache.get_stats().evictions == 1


def test_resolver_protocol():
    resolver = MockResolver()
    assert isinstance(resolver, DNSResolverProtocol)
    
    context = ResolutionContext(max_depth=5)
    context.increment_depth()
    assert context.current_depth == 1
    
    context.record_cname("www.example.com")
    assert context.cname_chain == ["www.example.com"]
    
    result = resolver.resolve("example.com", "A", context)
    assert result.domain_name == "example.com"
    assert result.answers == ["93.184.216.34"]
    assert result.rcode == 0
