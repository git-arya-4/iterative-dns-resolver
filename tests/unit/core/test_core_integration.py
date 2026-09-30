"""
Task 5.8: Core Resolver End-to-End Integration Tests.
"""

import time
import pytest
from idns.core import CoreResolverScaffold
from idns.contracts.transport import DNSTransportProtocol, ServerAddress, TransportConfig, TransportResult
from idns.model import DNSMessage, DNSHeader, DNSQuestion, DNSName, ARecord, AAAARecord, CNAMERecord, SOARecord, NSRecord
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

# --- REGRESSION TESTS FOR PHASE 5 BUG FIXES ---

def test_a_multi_hop_cname_across_resolver_calls(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("a.com.", "A", [CNAMERecord(DNSName("a.com"), DNSName("b.com"), 300)])
    trans.add_response("b.com.", "A", [CNAMERecord(DNSName("b.com"), DNSName("c.com"), 300)])
    trans.add_response("c.com.", "A", [ARecord(DNSName("c.com"), "1.2.3.4", 300)])
    r1 = res.resolve("a.com.", "A")
    assert len(r1.answers) == 3
    assert r1.answers[2].address == "1.2.3.4"

def test_b_three_node_cname_loop(resolver_and_transport):
    res, trans = resolver_and_transport
    trans.add_response("l1.com.", "A", [CNAMERecord(DNSName("l1.com"), DNSName("l2.com"), 300)])
    trans.add_response("l2.com.", "A", [CNAMERecord(DNSName("l2.com"), DNSName("l3.com"), 300)])
    trans.add_response("l3.com.", "A", [CNAMERecord(DNSName("l3.com"), DNSName("l1.com"), 300)])
    with pytest.raises(CNAMELoopError):
        res.resolve("l1.com.", "A")

def test_d_rfc2308_ttl_calculation(resolver_and_transport):
    res, trans = resolver_and_transport
    # SOA TTL is 300, minimum is 20. Expected negative TTL is 20.
    trans.add_response("neg.com.", "A", [], rcode=3, authorities=[
        SOARecord(DNSName("neg.com"), DNSName("ns"), DNSName("admin"), 1, 3600, 600, 86400, 20, ttl=300)
    ])
    r1 = res.resolve("neg.com.", "A")
    assert r1.is_nxdomain

    from idns.contracts.cache import CacheKey
    entry = res.cache.get(CacheKey.from_query("neg.com.", "A"))
    assert entry.ttl_seconds == 20

class IterativeFakeTransport(DNSTransportProtocol):
    def __init__(self):
        self.calls = []

    def send_query(self, server, query, config=None):
        msg = DNSMessageDecoder.decode(query)
        q = msg.questions[0]
        qname = q.qname.value.lower()
        self.calls.append((server.name, qname, q.qtype.upper()))

        if server.ip == "10.0.0.1":
            raise DNSTimeoutError(server.ip, 2.0)

        if server.name == "a.root-servers.net":
            if qname.endswith(".com") or qname == "com":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName("com"), DNSName("a.tld-servers.net"), 300)],
                    additionals=[ARecord(DNSName("a.tld-servers.net"), "192.5.6.30", 300)]
                )
            else:
                ans = DNSMessage(header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=3), questions=msg.questions)

        elif server.name == "a.tld-servers.net":
            if qname.endswith("example.com") or qname == "example.com":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName("example.com"), DNSName("ns1.example.com"), 300)],
                    additionals=[ARecord(DNSName("ns1.example.com"), "203.0.113.1", 300)]
                )
            elif qname.endswith("failover.com") or qname == "failover.com":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[
                        NSRecord(DNSName("failover.com"), DNSName("ns1.failover.com"), 300),
                        NSRecord(DNSName("failover.com"), DNSName("ns2.failover.com"), 300)
                    ],
                    additionals=[
                        ARecord(DNSName("ns1.failover.com"), "10.0.0.1", 300),
                        ARecord(DNSName("ns2.failover.com"), "203.0.113.2", 300)
                    ]
                )
            elif qname.endswith("allfail.com") or qname == "allfail.com":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[
                        NSRecord(DNSName("allfail.com"), DNSName("ns1.allfail.com"), 300),
                        NSRecord(DNSName("allfail.com"), DNSName("ns2.allfail.com"), 300)
                    ],
                    additionals=[
                        ARecord(DNSName("ns1.allfail.com"), "10.0.0.1", 300),
                        ARecord(DNSName("ns2.allfail.com"), "10.0.0.1", 300)
                    ]
                )
            else:
                ans = DNSMessage(header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=3), questions=msg.questions)

        elif server.name == "ns1.example.com":
            ans = DNSMessage(
                header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                questions=msg.questions,
                answers=[ARecord(DNSName("example.com"), "9.9.9.9", 300)]
            )
        elif server.name == "ns2.failover.com":
            ans = DNSMessage(
                header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                questions=msg.questions,
                answers=[ARecord(DNSName("failover.com"), "8.8.8.8", 300)]
            )
        else:
            ans = DNSMessage(header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=2), questions=msg.questions)

        raw = DNSMessageEncoder.encode(ans)
        return TransportResult(raw, server, 10.0)

    def send_query_with_fallback(self, servers, query, config=None):
        for server in servers:
            try:
                return self.send_query(server, query, config)
            except DNSTimeoutError:
                continue
        raise DNSTimeoutError("all_servers", 2.0)

def test_e_authoritative_timeout_alternate_succeeds_and_g_iterative_path():
    transport = IterativeFakeTransport()
    cache = InMemoryDNSCache()
    resolver = CoreResolverScaffold(transport=transport, cache=cache)
    resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
    from idns.iterative.engine import IterativeEngine
    from idns.core.cache_aware import CacheAwareResolver
    resolver.resolver_chain = CacheAwareResolver(cache, IterativeEngine(transport, resolver.root_servers))

    result = resolver.resolve("failover.com.", "A")
    assert result.answers[0].address == "8.8.8.8"

    # Verify the iterative path was actually taken!
    server_names = [call[0] for call in transport.calls]
    assert "a.root-servers.net" in server_names
    assert "a.tld-servers.net" in server_names
    assert "ns1.failover.com" in server_names
    assert "ns2.failover.com" in server_names

def test_f_all_authoritative_servers_fail():
    transport = IterativeFakeTransport()
    cache = InMemoryDNSCache()
    resolver = CoreResolverScaffold(transport=transport, cache=cache)
    resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
    from idns.iterative.engine import IterativeEngine
    from idns.core.cache_aware import CacheAwareResolver
    resolver.resolver_chain = CacheAwareResolver(cache, IterativeEngine(transport, resolver.root_servers))

    with pytest.raises(DNSTimeoutError):
        resolver.resolve("allfail.com.", "A")
