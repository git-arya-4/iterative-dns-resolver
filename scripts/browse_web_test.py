"""Task 9.2: Browse web through local DNS server.

Starts the iterative DNS resolver as a local UDP server on an ephemeral port,
resolves a target domain through it with an explicit ``nslookup``-style UDP
query, then makes a real HTTPS request to the resolved IP address using
``urllib`` with a manually set ``Host`` header.  This proves that the DNS
server produces addresses usable for real web traffic.

Usage (from repo root):
    PYTHONPATH=src python scripts/browse_web_test.py [--domain example.com] [--output experiments/os_integration/results.json]

The script does NOT modify OS-level DNS settings — it uses an explicit socket
query and a manual Host-header HTTP request.  It is safe to run without
administrator privileges.
"""

import argparse
import json
import socket
import ssl
import sys
import threading
import urllib.request
from pathlib import Path

# Ensure src/ is importable when invoked directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from idns.cache import InMemoryDNSCache
from idns.core import CoreResolver
from idns.model import DNSHeader, DNSMessage, DNSName, DNSQuestion
from idns.server import UDPDNSServer
from idns.transport.udp import UDPTransport
from idns.wire import DNSMessageDecoder, DNSMessageEncoder


def _resolve_via_local_server(host: str, port: int, domain: str) -> str:
    """Send an explicit A-record query to the local DNS server and return the first IP."""
    query = DNSMessage(
        header=DNSHeader(transaction_id=0xBEEF, rd=1),
        questions=[DNSQuestion(DNSName(domain), "A", "IN")],
    )
    raw_query = DNSMessageEncoder.encode(query)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10.0)
        sock.sendto(raw_query, (host, port))
        raw_response, _ = sock.recvfrom(4096)

    response = DNSMessageDecoder.decode(raw_response)
    if response.header.rcode != 0:
        raise RuntimeError(f"DNS query failed with rcode {response.header.rcode}")
    for answer in response.answers:
        if getattr(answer, "record_type", None) == "A":
            return answer.address
    raise RuntimeError(f"No A record returned for {domain}")


def _https_get(ip: str, domain: str) -> dict:
    """Make a real HTTPS GET request to *ip* with ``Host: <domain>``."""
    ctx = ssl.create_default_context()
    # Wrap a socket connected to the IP so SNI and Host match the domain.
    raw_sock = socket.create_connection((ip, 443), timeout=10)
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=domain)
    try:
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: idns-browse-test/1.0\r\n"
            f"\r\n"
        )
        tls_sock.sendall(request.encode())
        chunks = []
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        tls_sock.close()

    raw = b"".join(chunks)
    status_line = raw.split(b"\r\n", 1)[0].decode(errors="replace")
    return {
        "status_line": status_line,
        "bytes_received": len(raw),
        "returncode": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Browse web through local DNS server")
    parser.add_argument("--domain", default="example.com", help="Domain to resolve and fetch")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON results to this path")
    args = parser.parse_args()

    domain = args.domain
    hints_path = Path("config/root_hints.json")

    resolver = CoreResolver(
        root_hints_path=hints_path,
        transport=UDPTransport(),
        cache=InMemoryDNSCache(),
    )

    server = UDPDNSServer(resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Wait for the server to bind an ephemeral port
    deadline = __import__("time").time() + 2
    while server.port == 0 and __import__("time").time() < deadline:
        __import__("time").sleep(0.01)
    assert server.port != 0, "Server failed to bind"

    result: dict = {"server_port": server.port}
    try:
        # Step 1: DNS resolution through local server
        ip = _resolve_via_local_server("127.0.0.1", server.port, domain)
        result["resolver_answer_ip"] = ip
        print(f"[OK] DNS resolved {domain} -> {ip} via local server :{server.port}")

        # Step 2: HTTPS request to the resolved IP with Host header
        https_result = _https_get(ip, domain)
        result["https_request"] = https_result
        print(f"[OK] HTTPS GET {domain} ({ip}): {https_result['status_line']}  ({https_result['bytes_received']} bytes)")

    except Exception as exc:
        result["error"] = str(exc)
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    finally:
        server.close()
        thread.join(timeout=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
