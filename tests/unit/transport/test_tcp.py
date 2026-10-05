from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.transport import ServerAddress, TransportConfig
from idns.errors import TransportError
from idns.transport.tcp import TCPTransport


def make_dns_response(transaction_id: int = 0x1234) -> bytes:
    return (
        transaction_id.to_bytes(2, "big")
        + b"\x80\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def test_tcp_transport_sends_length_prefixed_query():
    transport = TCPTransport()

    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    response = make_dns_response()

    mock_socket = MagicMock()
    mock_socket.__enter__.return_value = mock_socket

    def recv(size):
        if size == 2:
            return len(response).to_bytes(2, "big")
        return response

    mock_socket.recv.side_effect = recv

    with patch(
        "idns.transport.tcp.socket.socket",
        return_value=mock_socket,
    ):
        result = transport.send_query(
            ServerAddress("192.0.2.53"),
            query,
        )

    mock_socket.connect.assert_called_once_with(
        ("192.0.2.53", 53)
    )

    mock_socket.sendall.assert_called_once_with(
        len(query).to_bytes(2, "big") + query
    )

    assert result.raw_response == response
    assert result.server_used.ip == "192.0.2.53"
    assert result.is_tcp is True


def test_tcp_transport_rejects_transaction_id_mismatch():
    transport = TCPTransport()

    query = b"\x12\x34\x00\x00"
    response = make_dns_response(transaction_id=0x5678)

    mock_socket = MagicMock()
    mock_socket.__enter__.return_value = mock_socket

    def recv(size):
        if size == 2:
            return len(response).to_bytes(2, "big")
        return response

    mock_socket.recv.side_effect = recv

    with patch(
        "idns.transport.tcp.socket.socket",
        return_value=mock_socket,
    ):
        with pytest.raises(TransportError):
            transport.send_query(
                ServerAddress("192.0.2.53"),
                query,
            )


def test_tcp_transport_rejects_short_response():
    transport = TCPTransport()

    query = b"\x12\x34\x00\x00"
    response = b"\x12\x34\x80\x00"

    mock_socket = MagicMock()
    mock_socket.__enter__.return_value = mock_socket

    def recv(size):
        if size == 2:
            return len(response).to_bytes(2, "big")
        return response

    mock_socket.recv.side_effect = recv

    with patch(
        "idns.transport.tcp.socket.socket",
        return_value=mock_socket,
    ):
        with pytest.raises(TransportError):
            transport.send_query(
                ServerAddress("192.0.2.53"),
                query,
            )


def test_tcp_transport_uses_configured_timeout():
    transport = TCPTransport()

    query = b"\x12\x34\x00\x00"
    response = make_dns_response()

    mock_socket = MagicMock()
    mock_socket.__enter__.return_value = mock_socket

    def recv(size):
        if size == 2:
            return len(response).to_bytes(2, "big")
        return response

    mock_socket.recv.side_effect = recv

    config = TransportConfig(timeout_seconds=5.0)

    with patch(
        "idns.transport.tcp.socket.socket",
        return_value=mock_socket,
    ):
        transport.send_query(
            ServerAddress("192.0.2.53"),
            query,
            config,
        )

    mock_socket.settimeout.assert_called_once_with(5.0)
# ---------------------------------------------------------------------------
# TCP edge-case coverage requested in Phase 7.2 review
# ---------------------------------------------------------------------------

class FakeTCPSocket:
    def __init__(self, *, recv_chunks=None, connect_error=None):
        self.recv_chunks = list(recv_chunks or [])
        self.connect_error = connect_error
        self.timeout = None
        self.connected_to = None
        self.sent_data = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected_to = address
        if self.connect_error is not None:
            raise self.connect_error

    def sendall(self, data):
        self.sent_data = data

    def recv(self, size):
        if not self.recv_chunks:
            return b""
        return self.recv_chunks.pop(0)


def _tcp_response(
    *,
    transaction_id=0x1234,
    flags=0x8000,
    body=b"",
):
    payload = (
        transaction_id.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + body
    )
    return len(payload).to_bytes(2, "big") + payload


def test_tcp_transport_handles_fragmented_response(monkeypatch):
    import idns.transport.tcp as tcp_module
    from idns.contracts.transport import ServerAddress
    from idns.transport.tcp import TCPTransport

    response = _tcp_response(transaction_id=0x1234)

    fake_socket = FakeTCPSocket(
        recv_chunks=[
            b"\x00",
            b"\x0c",
            response[2:5],
            response[5:8],
            response[8:],
        ]
    )

    monkeypatch.setattr(
        tcp_module.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")
    query = b"\x12\x34" + b"\x00" * 10

    result = transport.send_query(server, query)

    assert result.raw_response == response[2:]
    assert result.server_used == server
    assert result.is_tcp is True


def test_tcp_transport_converts_socket_timeout_to_dns_timeout(monkeypatch):
    import socket
    import idns.transport.tcp as tcp_module
    from idns.contracts.transport import ServerAddress
    from idns.errors import DNSTimeoutError
    from idns.transport.tcp import TCPTransport

    fake_socket = FakeTCPSocket(
        connect_error=socket.timeout("timed out")
    )

    monkeypatch.setattr(
        tcp_module.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(DNSTimeoutError):
        transport.send_query(
            server,
            b"\x12\x34" + b"\x00" * 10,
        )


def test_tcp_transport_converts_socket_error_to_server_unreachable(
    monkeypatch,
):
    import idns.transport.tcp as tcp_module
    from idns.contracts.transport import ServerAddress
    from idns.errors import ServerUnreachableError
    from idns.transport.tcp import TCPTransport

    fake_socket = FakeTCPSocket(
        connect_error=OSError("connection refused")
    )

    monkeypatch.setattr(
        tcp_module.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(ServerUnreachableError):
        transport.send_query(
            server,
            b"\x12\x34" + b"\x00" * 10,
        )


def test_tcp_transport_rejects_non_response_packet(monkeypatch):
    import idns.transport.tcp as tcp_module
    from idns.contracts.transport import ServerAddress
    from idns.errors import TransportError
    from idns.transport.tcp import TCPTransport

    response = _tcp_response(
        transaction_id=0x1234,
        flags=0x0000,
    )

    fake_socket = FakeTCPSocket(
        recv_chunks=[
            response[:2],
            response[2:],
        ]
    )

    monkeypatch.setattr(
        tcp_module.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(TransportError, match="response flag"):
        transport.send_query(
            server,
            b"\x12\x34" + b"\x00" * 10,
        )


def test_tcp_transport_rejects_connection_closed_before_complete_response(
    monkeypatch,
):
    import idns.transport.tcp as tcp_module
    from idns.contracts.transport import ServerAddress
    from idns.errors import ServerUnreachableError
    from idns.transport.tcp import TCPTransport

    response_length = b"\x00\x0c"

    fake_socket = FakeTCPSocket(
        recv_chunks=[
            response_length,
            b"",
        ]
    )

    monkeypatch.setattr(
        tcp_module.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(
        ServerUnreachableError,
        match="complete response",
    ):
        transport.send_query(
            server,
            b"\x12\x34" + b"\x00" * 10,
        )


def test_tcp_transport_rejects_oversized_query():
    from idns.contracts.transport import ServerAddress
    from idns.errors import TransportError
    from idns.transport.tcp import TCPTransport

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(TransportError, match="too large"):
        transport.send_query(
            server,
            b"\x12\x34" + b"\x00" * 65534,
        )


def test_tcp_transport_rejects_query_shorter_than_transaction_id():
    from idns.contracts.transport import ServerAddress
    from idns.errors import TransportError
    from idns.transport.tcp import TCPTransport

    transport = TCPTransport()
    server = ServerAddress("192.0.2.53")

    with pytest.raises(TransportError, match="too short"):
        transport.send_query(
            server,
            b"\x12",
        )
