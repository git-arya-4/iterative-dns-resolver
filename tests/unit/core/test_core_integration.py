"""
Task 5.8: Core Resolver End-to-End Integration Tests.
"""

import time
import pytest
from idns.core import CoreResolverScaffold
from idns.contracts.transport import DNSTransportProtocol, ServerAddress, TransportConfig, TransportResult
from idns.model import DNSMessage, DNSHeader, DNSQuestion, DNSName, ARecord, AAAARecord, CNAMERecord, SOARecord
from idns.cache import InMemoryDNSCache
from idns.wire.message_encoder import DNSMessageEncoder
from idns.wire.message_decoder import DNSMessageDecoder
from idns.errors import ResolutionError, ConfigError, MaxDepthExceededError, CNAMELoopError, DNSTimeoutError

class FakeTransport(DNSTransportProtocol):
    def __init__(self):
        self.calls = 0
        self.mock_responses = {}
        
    def add_response(self, qname, qtype, records, rcode=0, authorities=None):
        self.mock_responses[(qname.lower().rstrip("."), qtype.upper())] = (records, rcode, authorities or [])
        
    def send_query(self, server, query, config=None):
        self.calls += 1
        msg = DNSMessageDecoder.decode(query)
        q = msg.questions[0]
        
        if server.ip == "timeout":
            raise DNSTimeoutError(server.ip, 2.0)
            
        key = (q.qname.value.lower(), q.qtype.upper())
        if key in self.mock_responses:
            records, rcode, authorities = self.mock_responses[key]
            ans = DNSMessage(
                header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=rcode),
                questions=msg.questions,
                answers=records,
                authorities=authorities
            )
        else:
            ans = DNSMessage(
                header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=3), # NXDOMAIN
                questions=msg.questions
            )
            
        raw = DNSMessageEncoder.encode(ans)
        return TransportResult(raw, server, 10.0)

    def send_query_with_fallback(self, servers, query, config=None):
        for server in servers:
            try:
                return self.send_query(server, query, config)
            except DNSTimeoutError:
                continue
        raise DNSTimeoutError("all_servers", 2.0)


@pytest.fixture
def resolver_and_transport():
    transport = FakeTransport()
    cache = InMemoryDNSCache()
    cache.clear()
    resolver = CoreResolverScaffold(transport=transport, cache=cache)
    resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
    # Force re-init of chain since we injected directly
    from idns.iterative.engine import IterativeEngine
    from idns.core.cache_aware import CacheAwareResolver
    engine = IterativeEngine(transport, resolver.root_servers)
    resolver.resolver_chain = CacheAwareResolver(cache, engine)
    
    # Pre-configure Root to delegate everything to "auth"
    transport.add_response(".", "A", [], rcode=0, authorities=[])
    
    return resolver, transport


def test_01_direct_a(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("example.com.", "A", [ARecord(DNSName("example.com"), "1.2.3.4", 300)])
    result = res.resolve("example.com.", "A")
    assert result.answers[0].address == "1.2.3.4"
    assert not result.is_cache_hit

def test_02_direct_aaaa(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("example.com.", "AAAA", [AAAARecord(DNSName("example.com"), "::1", 300)])
    result = res.resolve("example.com.", "AAAA")
    assert result.answers[0].address == "::1"
    assert result.record_type == "AAAA"

def test_03_positive_cache_hit_and_04_miss(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("example.com.", "A", [ARecord(DNSName("example.com"), "1.2.3.4", 300)])
    
    r1 = res.resolve("example.com.", "A")
    assert not r1.is_cache_hit
    assert trans.calls == 1
    
    r2 = res.resolve("example.com.", "A")
    assert r2.is_cache_hit
    assert trans.calls == 1  # No new network call!

def test_06_ttl_expiration(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("exp.com.", "A", [ARecord(DNSName("exp.com"), "1.2.3.4", 1)])
    res.resolve("exp.com.", "A")
    
    # Force expire
    from idns.contracts.cache import CacheKey
    entry = res.cache.get(CacheKey.from_query("exp.com.", "A", "IN"))
    entry.creation_timestamp -= 10
    
    r2 = res.resolve("exp.com.", "A")
    assert not r2.is_cache_hit

def test_07_nxdomain_and_08_cache_hit(resolver_and_transport):
    res, trans = resolver_and_transport
    r1 = res.resolve("nx.com.", "A")
    assert r1.is_nxdomain
    assert r1.rcode == 3
    assert trans.calls == 1
    
    r2 = res.resolve("nx.com.", "A")
    assert r2.is_cache_hit
    assert r2.is_nxdomain
    assert trans.calls == 1

def test_09_nodata_and_10_cache_hit(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("nodata.com.", "A", [], rcode=0, authorities=[SOARecord(DNSName("nodata.com"), DNSName("ns"), DNSName("admin"), 1, 3600, 600, 86400, 300, ttl=300)])
    r1 = res.resolve("nodata.com.", "A")
    assert not r1.is_nxdomain
    assert not r1.answers
    assert r1.rcode == 0
    assert trans.calls == 1
    
    r2 = res.resolve("nodata.com.", "A")
    assert r2.is_cache_hit
    assert not r2.answers
    assert trans.calls == 1

def test_11_nodata_qtype_isolation(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("nodata.com.", "A", [], rcode=0, authorities=[SOARecord(DNSName("nodata.com"), DNSName("ns"), DNSName("admin"), 1, 3600, 600, 86400, 300, ttl=300)])
    trans.add_response("nodata.com.", "AAAA", [AAAARecord(DNSName("nodata.com"), "::1", 300)])
    
    res.resolve("nodata.com.", "A")
    r2 = res.resolve("nodata.com.", "AAAA")
    assert not r2.is_cache_hit  # Should fetch AAAA from network
    assert r2.answers[0].address == "::1"

def test_12_cname(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("alias.com.", "A", [CNAMERecord(DNSName("alias.com"), DNSName("target.com"), 300)])
    trans.add_response("target.com.", "A", [ARecord(DNSName("target.com"), "1.2.3.4", 300)])
    
    r1 = res.resolve("alias.com.", "A")
    assert len(r1.answers) == 2
    assert r1.answers[1].address == "1.2.3.4"

def test_14_same_response_cname(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("alias.com.", "A", [
        CNAMERecord(DNSName("alias.com"), DNSName("target.com"), 300),
        ARecord(DNSName("target.com"), "1.2.3.4", 300)
    ])
    
    r1 = res.resolve("alias.com.", "A")
    assert len(r1.answers) == 2
    assert trans.calls == 1  # Only 1 network call needed

def test_15_explicit_cname_query(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("alias.com.", "CNAME", [CNAMERecord(DNSName("alias.com"), DNSName("target.com"), 300)])
    r1 = res.resolve("alias.com.", "CNAME")
    assert len(r1.answers) == 1  # Does NOT follow to A record

def test_16_cname_cycle(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("a.com.", "A", [CNAMERecord(DNSName("a.com"), DNSName("b.com"), 300)])
    trans.add_response("b.com.", "A", [CNAMERecord(DNSName("b.com"), DNSName("a.com"), 300)])
    with pytest.raises(CNAMELoopError):
        res.resolve("a.com.", "A")

def test_17_cname_depth(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("d1.com.", "A", [CNAMERecord(DNSName("d1.com"), DNSName("d2.com"), 300)])
    trans.add_response("d2.com.", "A", [CNAMERecord(DNSName("d2.com"), DNSName("d3.com"), 300)])
    trans.add_response("d3.com.", "A", [CNAMERecord(DNSName("d3.com"), DNSName("d4.com"), 300)])
    ctx = res.create_context()
    ctx.max_depth = 2
    with pytest.raises(MaxDepthExceededError):
        res.resolve("d1.com.", "A", context=ctx)

def test_19_iterative_failure(resolver_and_transport):
    res, trans = resolver_and_transport
    res.root_servers = [{"ipv4": "timeout", "name": "root"}]
    # Force re-init to pick up the broken root server
    from idns.iterative.engine import IterativeEngine
    from idns.core.cache_aware import CacheAwareResolver
    engine = IterativeEngine(trans, res.root_servers)
    res.resolver_chain = CacheAwareResolver(res.cache, engine)

    with pytest.raises(DNSTimeoutError):
        res.resolve("example.com.", "A")

def test_25_unsupported_invalid(resolver_and_transport):
    res, trans = resolver_and_transport
    with pytest.raises(ResolutionError):
        res.resolve("", "A")
    with pytest.raises(ResolutionError):
        res.resolve("example.com", "")
