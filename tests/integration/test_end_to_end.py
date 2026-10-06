import socket
import threading
import time

import pytest

from idns.cache import InMemoryDNSCache
from idns.core import CoreResolverScaffold
from idns.core.cache_aware import CacheAwareResolver
from idns.iterative.engine import IterativeEngine
from idns.server import TCPDNSServer, UDPDNSServer
from idns.transport.udp import UDPTransport
from idns.transport.tcp import TCPTransport
from idns.wire import DNSMessageDecoder, DNSMessageEncoder
from tests.integration.test_server_lifecycle import recv_exact, wait_for_port
from tests.unit.core.test_core_integration import IterativeFakeTransport


class E2EFakeTransport(IterativeFakeTransport):
    def send_query(self, server, query, config=None):
        msg = DNSMessageDecoder.decode(query)
        q = msg.questions[0]
        qname = q.qname.value.lower()
        self.calls.append((server.name, qname, q.qtype.upper()))

        from idns.model import DNSMessage, DNSHeader, DNSName, ARecord, CNAMERecord, NSRecord, SOARecord
        from idns.errors import DNSTimeoutError
        from idns.contracts.transport import TransportResult

        if server.ip == "10.0.0.1" or server.ip == "timeout":
            raise DNSTimeoutError(server.ip, 2.0)

        # Root Server
        if server.name == "a.root-servers.net":
            if qname.endswith(".test") or qname == "test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName("test"), DNSName("a.tld-servers.net"), 300)],
                    additionals=[ARecord(DNSName("a.tld-servers.net"), "192.5.6.30", 300)]
                )
                raw = DNSMessageEncoder.encode(ans)
                return TransportResult(raw, server, 10.0)
            else:
                # Fallback to base logic for .com domains
                return super().send_query(server, query, config)

        # TLD Server
        elif server.name == "a.tld-servers.net":
            if qname.endswith("example.test") or qname == "example.test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName("example.test"), DNSName("ns1.example.test"), 300)],
                    additionals=[ARecord(DNSName("ns1.example.test"), "203.0.113.1", 300)]
                )
                raw = DNSMessageEncoder.encode(ans)
                return TransportResult(raw, server, 10.0)
            else:
                return super().send_query(server, query, config)

        # Auth Server
        elif server.name == "ns1.example.test":
            if qname == "alias.example.test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    answers=[CNAMERecord(DNSName("alias.example.test"), DNSName("target1.example.test"), 300)]
                )
            elif qname == "target1.example.test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    answers=[CNAMERecord(DNSName("target1.example.test"), DNSName("target2.example.test"), 300)]
                )
            elif qname == "target2.example.test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    answers=[ARecord(DNSName("target2.example.test"), "192.0.2.10", 300)]
                )
            elif qname == "nx.example.test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=3), # NXDOMAIN
                    questions=msg.questions,
                    authorities=[SOARecord(DNSName("example.test"), DNSName("ns1"), DNSName("admin"), 1, 3600, 600, 86400, 300, ttl=300)]
                )
            else:
                ans = DNSMessage(header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=2), questions=msg.questions) # SERVFAIL

            raw = DNSMessageEncoder.encode(ans)
            return TransportResult(raw, server, 10.0)

        # Fallback to IterativeFakeTransport for example.com, failover.com, etc
        return super().send_query(server, query, config)


@pytest.fixture
def end_to_end_setup():
    transport = E2EFakeTransport()
    cache = InMemoryDNSCache()
    cache.clear()
    resolver = CoreResolverScaffold(transport=transport, cache=cache)
    resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
    resolver.resolver_chain = CacheAwareResolver(
        cache, IterativeEngine(transport, resolver.root_servers)
    )
    return resolver, transport, cache


def _build_query(qname: str, qtype: str = "A") -> bytes:
    from idns.model import DNSHeader, DNSMessage, DNSName, DNSQuestion
    from idns.wire import DNSMessageEncoder

    msg = DNSMessage(
        header=DNSHeader(transaction_id=0x1234, rd=1),
        questions=[DNSQuestion(DNSName(qname), qtype, "IN")]
    )
    return DNSMessageEncoder.encode(msg)


def test_happy_path_iterative_flow_udp(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)
            packet = _build_query("example.com.")
            client.sendto(packet, (server.host, server.port))
            raw_response, _ = client.recvfrom(4096)

        response = DNSMessageDecoder.decode(raw_response)

        # 7.5.5 DNS Wire Validation
        assert response.header.transaction_id == 0x1234
        assert response.header.qr == 1
        assert response.header.rcode == 0
        assert response.header.qdcount == 1
        assert response.header.ancount == 1
        assert response.header.nscount == 0
        assert response.header.arcount == 0

        q = response.questions[0]
        assert q.qname.value == "example.com"
        assert q.qtype == "A"
        assert q.qclass == "IN"

        a = response.answers[0]
        assert a.name.value == "example.com"
        assert a.record_type == "A"
        assert a.address == "9.9.9.9"
        assert a.ttl == 300

        server_names = [call[0] for call in transport.calls]
        assert "a.root-servers.net" in server_names
    finally:
        server.close()
        thread.join(timeout=2.0)


def test_end_to_end_caching_udp(end_to_end_setup):
    resolver, transport, cache = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)
            packet = _build_query("example.com.")

            client.sendto(packet, (server.host, server.port))
            raw_response1, _ = client.recvfrom(4096)
            resp1 = DNSMessageDecoder.decode(raw_response1)
            assert resp1.answers[0].address == "9.9.9.9"

            calls_after_first = len(transport.calls)
            assert calls_after_first > 0

            client.sendto(packet, (server.host, server.port))
            raw_response2, _ = client.recvfrom(4096)
            resp2 = DNSMessageDecoder.decode(raw_response2)
            assert resp2.answers[0].address == "9.9.9.9"

            assert len(transport.calls) == calls_after_first
    finally:
        server.close()
        thread.join(timeout=2.0)


def test_resilience_fallback_tcp(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = TCPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.create_connection((server.host, server.port), timeout=2.0) as client:
            packet = _build_query("failover.com.")
            client.sendall(len(packet).to_bytes(2, "big") + packet)

            response_length = int.from_bytes(recv_exact(client, 2), "big")
            raw_response = recv_exact(client, response_length)

        response = DNSMessageDecoder.decode(raw_response)
        assert response.header.rcode == 0
        assert len(response.answers) == 1
        assert response.answers[0].address == "8.8.8.8"

        server_names = [call[0] for call in transport.calls]
        assert "ns1.failover.com" in server_names
        assert "ns2.failover.com" in server_names
    finally:
        server.close()
        thread.join(timeout=2.0)


# 7.4.1 CNAME Chain - Required
def test_cname_chain_multi_hop_e2e(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)
            packet = _build_query("alias.example.test.")
            client.sendto(packet, (server.host, server.port))
            raw_response, _ = client.recvfrom(4096)

        response = DNSMessageDecoder.decode(raw_response)
        assert response.header.rcode == 0

        # We expect 3 answers: alias -> target1, target1 -> target2, target2 -> 192.0.2.10
        assert len(response.answers) == 3
        assert response.answers[2].record_type == "A"
        assert response.answers[2].address == "192.0.2.10"

        # Verify transport chased all of them!
        qnames = [call[1] for call in transport.calls]
        assert "alias.example.test" in qnames
        assert "target1.example.test" in qnames
        assert "target2.example.test" in qnames
    finally:
        server.close()
        thread.join(timeout=2.0)


# 7.4.2 Negative Cache - Required
def test_negative_cache_e2e(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)
            packet = _build_query("nx.example.test.")

            # Request 1
            client.sendto(packet, (server.host, server.port))
            raw_response1, _ = client.recvfrom(4096)
            resp1 = DNSMessageDecoder.decode(raw_response1)
            assert resp1.header.rcode == 3 # NXDOMAIN

            calls_after_first = len(transport.calls)
            assert calls_after_first > 0

            # Request 2
            client.sendto(packet, (server.host, server.port))
            raw_response2, _ = client.recvfrom(4096)
            resp2 = DNSMessageDecoder.decode(raw_response2)
            assert resp2.header.rcode == 3 # NXDOMAIN

            # Verify no new transport calls were made!
            assert len(transport.calls) == calls_after_first
    finally:
        server.close()
        thread.join(timeout=2.0)


# 7.4.3 Malformed Request - Required
def test_malformed_request_e2e(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)

            # Send garbage
            client.sendto(b"this is absolute garbage not a dns packet", (server.host, server.port))

            # Receive FORMERR
            raw_response, _ = client.recvfrom(4096)
            response = DNSMessageDecoder.decode(raw_response)
            assert response.header.rcode == 1 # FORMERR

            # Ensure server is still alive
            packet = _build_query("example.com.")
            client.sendto(packet, (server.host, server.port))
            raw_response2, _ = client.recvfrom(4096)
            resp2 = DNSMessageDecoder.decode(raw_response2)
            assert resp2.header.rcode == 0
    finally:
        server.close()
        thread.join(timeout=2.0)


# 7.4.4 Resolver Failure -> SERVFAIL - Required
def test_resolver_failure_servfail_e2e(end_to_end_setup):
    resolver, transport, _ = end_to_end_setup
    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)

            # Intentionally break the resolver by causing a top-level timeout
            original_roots = resolver.root_servers
            resolver.root_servers = [{"ipv4": "timeout", "name": "bad"}]
            resolver.resolver_chain = CacheAwareResolver(
                resolver.cache, IterativeEngine(transport, resolver.root_servers)
            )

            # Send query that will fail completely
            packet = _build_query("example.com.")
            client.sendto(packet, (server.host, server.port))
            raw_response, _ = client.recvfrom(4096)
            response = DNSMessageDecoder.decode(raw_response)

            # Must return SERVFAIL
            assert response.header.rcode == 2 # SERVFAIL

            # Restore and verify it stays alive
            resolver.root_servers = original_roots
            resolver.resolver_chain = CacheAwareResolver(
                resolver.cache, IterativeEngine(transport, resolver.root_servers)
            )
            client.sendto(packet, (server.host, server.port))
            raw_response2, _ = client.recvfrom(4096)
            resp2 = DNSMessageDecoder.decode(raw_response2)
            assert resp2.header.rcode == 0 # OK
    finally:
        server.close()
        thread.join(timeout=2.0)


# 7.4.5 Real TC=1 UDP -> TCP Fallback - Required
def test_real_tc_fallback_udp_to_tcp():
    # 1. Setup local mock upstream server
    class MockUpstreamServer:
        def __init__(self):
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind(("127.0.0.1", 0))
            self.port = self.udp_sock.getsockname()[1]

            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind(("127.0.0.1", self.port))
            self.tcp_sock.listen(1)

            self.running = True
            self.udp_thread = threading.Thread(target=self._run_udp)
            self.tcp_thread = threading.Thread(target=self._run_tcp)
            self.udp_thread.start()
            self.tcp_thread.start()

            self.udp_received = False
            self.tcp_received = False

        def _run_udp(self):
            self.udp_sock.settimeout(1.0)
            while self.running:
                try:
                    data, addr = self.udp_sock.recvfrom(4096)
                    self.udp_received = True
                    # Return TC=1
                    from idns.model import DNSHeader, DNSMessage
                    from idns.wire import DNSMessageDecoder, DNSMessageEncoder
                    req = DNSMessageDecoder.decode(data)
                    ans = DNSMessage(header=DNSHeader(transaction_id=req.header.transaction_id, qr=1, tc=1, rcode=0), questions=req.questions)
                    self.udp_sock.sendto(DNSMessageEncoder.encode(ans), addr)
                except socket.timeout:
                    pass

        def _run_tcp(self):
            self.tcp_sock.settimeout(1.0)
            while self.running:
                try:
                    conn, _ = self.tcp_sock.accept()
                    with conn:
                        self.tcp_received = True
                        length_bytes = recv_exact(conn, 2)
                        length = int.from_bytes(length_bytes, "big")
                        data = recv_exact(conn, length)

                        # Return valid A record
                        from idns.model import DNSHeader, DNSMessage, ARecord, DNSName
                        from idns.wire import DNSMessageDecoder, DNSMessageEncoder
                        req = DNSMessageDecoder.decode(data)
                        ans = DNSMessage(
                            header=DNSHeader(transaction_id=req.header.transaction_id, qr=1, rcode=0),
                            questions=req.questions,
                            answers=[ARecord(DNSName("fallback.com"), "192.168.1.1", 300)]
                        )
                        raw = DNSMessageEncoder.encode(ans)
                        conn.sendall(len(raw).to_bytes(2, "big") + raw)
                except socket.timeout:
                    pass

        def close(self):
            self.running = False
            self.udp_thread.join()
            self.tcp_thread.join()
            self.udp_sock.close()
            self.tcp_sock.close()

    upstream = MockUpstreamServer()

    try:
        # 2. Setup real resolver with real transports pointing to upstream
        cache = InMemoryDNSCache()
        cache.clear()

        transport = UDPTransport() # The real transport will fallback to TCPTransport internally
        resolver = CoreResolverScaffold(transport=transport, cache=cache)
        resolver.root_servers = [{"ipv4": "127.0.0.1", "port": upstream.port, "name": "mock.root"}]
        resolver.resolver_chain = CacheAwareResolver(
            cache, IterativeEngine(transport, resolver.root_servers)
        )

        # 3. Start local UDP server
        local_server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
        local_thread = threading.Thread(target=local_server.serve_forever)
        local_thread.start()

        try:
            wait_for_port(local_server)

            # 4. Client queries local UDP server
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2.0)
                packet = _build_query("fallback.com.")
                client.sendto(packet, (local_server.host, local_server.port))
                raw_response, _ = client.recvfrom(4096)

            response = DNSMessageDecoder.decode(raw_response)

            # Verify final answer
            assert response.header.rcode == 0
            assert len(response.answers) == 1
            assert response.answers[0].address == "192.168.1.1"

            # Verify the fallback actually occurred locally!
            assert upstream.udp_received
            assert upstream.tcp_received
        finally:
            local_server.close()
            local_thread.join(timeout=2.0)
    finally:
        upstream.close()
