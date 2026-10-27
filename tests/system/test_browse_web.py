"""Task 9.2: System test – browse web through local DNS server.

This test proves the full pipeline works deterministically **without** hitting
the public Internet:

1.  A tiny HTTP server is started on a loopback ephemeral port.
2.  A local UDP DNS server is started with a fake transport that returns the
    HTTP server's address for ``browse.test``.
3.  A client resolves ``browse.test`` through the local DNS server.
4.  A client makes an HTTP GET request to the resolved IP address (with a
    ``Host: browse.test`` header).
5.  The test asserts that the HTTP response body is received correctly.

All sockets are loopback-only and cleaned up after the test.
"""

import http.server
import socket
import threading
import time

import pytest

from idns.cache import InMemoryDNSCache
from idns.core import CoreResolverScaffold
from idns.core.cache_aware import CacheAwareResolver
from idns.iterative.engine import IterativeEngine
from idns.model import (
    ARecord,
    DNSHeader,
    DNSMessage,
    DNSName,
    DNSQuestion,
    NSRecord,
)
from idns.server import UDPDNSServer
from idns.wire import DNSMessageDecoder, DNSMessageEncoder
from tests.integration.test_server_lifecycle import wait_for_port
from tests.unit.core.test_core_integration import IterativeFakeTransport
from idns.contracts.transport import TransportResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BROWSE_DOMAIN = "browse.test"
_HTTP_BODY = b"Hello from the local HTTP server!"


class _BrowseTestTransport(IterativeFakeTransport):
    """Extends the shared fake transport with a ``.test`` TLD for browse.test."""

    def __init__(self, http_ip: str):
        super().__init__()
        self._http_ip = http_ip

    def send_query(self, server, query, config=None):
        msg = DNSMessageDecoder.decode(query)
        q = msg.questions[0]
        qname = q.qname.value.lower()
        self.calls.append((server.name, qname, q.qtype.upper()))

        # Root → .test TLD referral
        if server.name == "a.root-servers.net":
            if qname.endswith(".test") or qname == "test":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName("test"), DNSName("a.tld-test.net"), 300)],
                    additionals=[ARecord(DNSName("a.tld-test.net"), "192.0.2.1", 300)],
                )
                return TransportResult(DNSMessageEncoder.encode(ans), server, 1.0)

        # TLD → browse.test authoritative referral
        if server.name == "a.tld-test.net":
            if qname.endswith(_BROWSE_DOMAIN) or qname == _BROWSE_DOMAIN:
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    authorities=[NSRecord(DNSName(_BROWSE_DOMAIN), DNSName("ns1.browse.test"), 300)],
                    additionals=[ARecord(DNSName("ns1.browse.test"), "203.0.113.10", 300)],
                )
                return TransportResult(DNSMessageEncoder.encode(ans), server, 1.0)

        # Authoritative answer for browse.test → HTTP server IP
        if server.name == "ns1.browse.test":
            if qname == _BROWSE_DOMAIN and q.qtype.upper() == "A":
                ans = DNSMessage(
                    header=DNSHeader(transaction_id=msg.header.transaction_id, qr=1, rcode=0),
                    questions=msg.questions,
                    answers=[ARecord(DNSName(_BROWSE_DOMAIN), self._http_ip, 300)],
                )
                return TransportResult(DNSMessageEncoder.encode(ans), server, 1.0)

        # Fall back to the parent for .com domains, etc.
        return super().send_query(server, query, config)


class _SimpleHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that returns a fixed response."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_HTTP_BODY)))
        self.end_headers()
        self.wfile.write(_HTTP_BODY)

    def log_message(self, format, *args):
        pass  # Suppress request logging during tests


def _build_dns_query(domain: str, qtype: str = "A") -> bytes:
    msg = DNSMessage(
        header=DNSHeader(transaction_id=0xCAFE, rd=1),
        questions=[DNSQuestion(DNSName(domain), qtype, "IN")],
    )
    return DNSMessageEncoder.encode(msg)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_browse_web_through_local_dns_server():
    """Full pipeline: DNS resolve → HTTP GET through the local DNS server."""

    # 1. Start a local HTTP server on an ephemeral port
    http_server = http.server.HTTPServer(("127.0.0.1", 0), _SimpleHTTPHandler)
    http_host, http_port = http_server.server_address
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    try:
        # 2. Start a local DNS server with fake transport routing browse.test → http_host
        transport = _BrowseTestTransport(http_ip=http_host)
        cache = InMemoryDNSCache()
        cache.clear()
        resolver = CoreResolverScaffold(transport=transport, cache=cache)
        resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
        resolver.resolver_chain = CacheAwareResolver(
            cache, IterativeEngine(transport, resolver.root_servers)
        )

        dns_server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
        dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
        dns_thread.start()

        try:
            wait_for_port(dns_server)

            # 3. Resolve browse.test through the local DNS server
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(
                    _build_dns_query(_BROWSE_DOMAIN),
                    ("127.0.0.1", dns_server.port),
                )
                raw_response, _ = sock.recvfrom(4096)

            response = DNSMessageDecoder.decode(raw_response)
            assert response.header.transaction_id == 0xCAFE
            assert response.header.qr == 1
            assert response.header.rcode == 0, f"DNS rcode = {response.header.rcode}"
            assert len(response.answers) >= 1

            resolved_ip = None
            for answer in response.answers:
                if getattr(answer, "record_type", None) == "A":
                    resolved_ip = answer.address
                    break
            assert resolved_ip is not None, "No A record in DNS response"
            assert resolved_ip == http_host

            # 4. Make an HTTP GET to the resolved IP with Host header
            conn = socket.create_connection((resolved_ip, http_port), timeout=2.0)
            try:
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {_BROWSE_DOMAIN}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                conn.sendall(request)

                chunks = []
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                conn.close()

            raw_http = b"".join(chunks)
            assert b"200 OK" in raw_http, f"Expected 200 OK, got: {raw_http[:80]}"
            assert _HTTP_BODY in raw_http, f"Expected body not found in HTTP response"

            # 5. Verify the transport was exercised (iterative traversal)
            server_names = [call[0] for call in transport.calls]
            assert "a.root-servers.net" in server_names
            assert "a.tld-test.net" in server_names
            assert "ns1.browse.test" in server_names

        finally:
            dns_server.close()
            dns_thread.join(timeout=2.0)
    finally:
        http_server.shutdown()
        http_thread.join(timeout=2.0)


def test_browse_web_dns_caching_on_repeat_http():
    """Second HTTP request should use cached DNS — no new transport calls."""

    http_server = http.server.HTTPServer(("127.0.0.1", 0), _SimpleHTTPHandler)
    http_host, http_port = http_server.server_address
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    try:
        transport = _BrowseTestTransport(http_ip=http_host)
        cache = InMemoryDNSCache()
        cache.clear()
        resolver = CoreResolverScaffold(transport=transport, cache=cache)
        resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
        resolver.resolver_chain = CacheAwareResolver(
            cache, IterativeEngine(transport, resolver.root_servers)
        )

        dns_server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
        dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
        dns_thread.start()

        try:
            wait_for_port(dns_server)
            dns_addr = ("127.0.0.1", dns_server.port)

            def _dns_resolve() -> str:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2.0)
                    sock.sendto(_build_dns_query(_BROWSE_DOMAIN), dns_addr)
                    raw, _ = sock.recvfrom(4096)
                resp = DNSMessageDecoder.decode(raw)
                for ans in resp.answers:
                    if getattr(ans, "record_type", None) == "A":
                        return ans.address
                raise AssertionError("No A record")

            def _http_get(ip: str) -> bytes:
                conn = socket.create_connection((ip, http_port), timeout=2.0)
                try:
                    conn.sendall(
                        f"GET / HTTP/1.1\r\nHost: {_BROWSE_DOMAIN}\r\nConnection: close\r\n\r\n".encode()
                    )
                    chunks = []
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                finally:
                    conn.close()
                return b"".join(chunks)

            # First request
            ip1 = _dns_resolve()
            body1 = _http_get(ip1)
            assert _HTTP_BODY in body1
            calls_after_first = len(transport.calls)
            assert calls_after_first > 0

            # Second request — DNS should be cached
            ip2 = _dns_resolve()
            body2 = _http_get(ip2)
            assert _HTTP_BODY in body2
            assert ip2 == ip1
            assert len(transport.calls) == calls_after_first, (
                "Expected zero new transport calls on cached repeat"
            )

        finally:
            dns_server.close()
            dns_thread.join(timeout=2.0)
    finally:
        http_server.shutdown()
        http_thread.join(timeout=2.0)


def test_browse_web_nxdomain_prevents_http():
    """DNS NXDOMAIN for a nonexistent domain prevents HTTP browsing."""

    transport = _BrowseTestTransport(http_ip="127.0.0.1")
    cache = InMemoryDNSCache()
    cache.clear()
    resolver = CoreResolverScaffold(transport=transport, cache=cache)
    resolver.root_servers = [{"ipv4": "198.41.0.4", "name": "a.root-servers.net"}]
    resolver.resolver_chain = CacheAwareResolver(
        cache, IterativeEngine(transport, resolver.root_servers)
    )

    dns_server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
    dns_thread.start()

    try:
        wait_for_port(dns_server)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(
                _build_dns_query("nonexistent.invalid"),
                ("127.0.0.1", dns_server.port),
            )
            raw_response, _ = sock.recvfrom(4096)

        response = DNSMessageDecoder.decode(raw_response)
        # NXDOMAIN (rcode=3) or SERVFAIL (rcode=2) — either way, no A record
        assert response.header.rcode in (2, 3), f"Expected NXDOMAIN/SERVFAIL, got rcode={response.header.rcode}"

        has_a = any(
            getattr(ans, "record_type", None) == "A"
            for ans in response.answers
        )
        assert not has_a, "Should not return an A record for a nonexistent domain"

    finally:
        dns_server.close()
        dns_thread.join(timeout=2.0)
