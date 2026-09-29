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