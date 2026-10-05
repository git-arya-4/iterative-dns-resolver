import socket
import threading
import time

import pytest

from idns.server import TCPDNSServer, UDPDNSServer
from idns.wire import DNSMessageDecoder, DNSMessageEncoder
from tests.unit.server.test_server import FakeResolver, query_packet


def wait_for_port(server):
    deadline = time.time() + 2
    while server.port == 0 and time.time() < deadline:
        time.sleep(0.01)
    assert server.port != 0


def recv_exact(client, size):
    """Read exactly ``size`` bytes from a stream socket."""
    data = bytearray()
    while len(data) < size:
        chunk = client.recv(size - len(data))
        if not chunk:
            raise ConnectionError("TCP connection closed before full response")
        data.extend(chunk)
    return bytes(data)


@pytest.mark.parametrize("server_type", [UDPDNSServer, TCPDNSServer])
def test_server_handles_real_request_and_shuts_down_cleanly(server_type):
    server = server_type(FakeResolver(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        wait_for_port(server)
        if server_type is UDPDNSServer:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(query_packet(), (server.host, server.port))
                raw_response, _ = client.recvfrom(4096)
        else:
            with socket.create_connection((server.host, server.port), timeout=2) as client:
                packet = query_packet()
                client.sendall(len(packet).to_bytes(2, "big") + packet)
                response_length = int.from_bytes(recv_exact(client, 2), "big")
                raw_response = recv_exact(client, response_length)
        response = DNSMessageDecoder.decode(raw_response)
        assert response.header.transaction_id == 0x1234
        assert response.header.qr == 1
        assert response.header.rcode == 0
        assert response.header.qdcount == 1
        assert len(response.questions) == 1
        assert response.questions[0].qname.value == "example.com"
        assert response.questions[0].qtype == "A"
    finally:
        server.close()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_tcp_server_accepts_new_clients_while_one_client_is_idle():
    server = TCPDNSServer(FakeResolver(), host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    idle_client = None
    active_client = None
    try:
        wait_for_port(server)
        idle_client = socket.create_connection((server.host, server.port), timeout=2)
        active_client = socket.create_connection((server.host, server.port), timeout=2)
        active_client.settimeout(2)
        packet = query_packet()
        active_client.sendall(len(packet).to_bytes(2, "big") + packet)

        response_length = int.from_bytes(recv_exact(active_client, 2), "big")
        response = DNSMessageDecoder.decode(recv_exact(active_client, response_length))
        assert response.header.transaction_id == 0x1234
        assert response.header.qr == 1
    finally:
        if idle_client is not None:
            idle_client.close()
        if active_client is not None:
            active_client.close()
        server.close()
        server_thread.join(timeout=2)
    assert not server_thread.is_alive()
