from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.transport import (
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.errors import (
    DNSTimeoutError,
    ServerUnreachableError,
    TransportError,
)
from idns.transport.udp import UDPTransport


SERVER = ServerAddress("192.0.2.1")
QUERY = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def make_response(
    transaction_id: int = 0x1234,
    tc: bool = False,
) -> bytes:
    flags = 0x8000

    if tc:
        flags |= 0x0200

    return (
        transaction_id.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def test_send_query_returns_response():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(),
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.raw_response == make_response()
    assert result.server_used == SERVER
    assert result.tc_bit_set is False


def test_send_query_falls_back_to_tcp_when_tc_is_set():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(tc=True),
        ("192.0.2.1", 53),
    )

    tcp_result = TransportResult(
        raw_response=make_response(tc=False),
        server_used=SERVER,
        rtt_ms=2.0,
        tc_bit_set=False,
        is_tcp=True,
    )

    with (
        patch("idns.transport.udp.socket.socket") as socket_mock,
        patch("idns.transport.udp.TCPTransport") as tcp_mock,
    ):
        socket_mock.return_value.__enter__.return_value = fake_socket

        tcp_mock.return_value.send_query.return_value = tcp_result

        result = UDPTransport().send_query(SERVER, QUERY)

    tcp_mock.return_value.send_query.assert_called_once_with(
        SERVER,
        QUERY,
        TransportConfig(),
    )

    assert result.is_tcp is True
    assert result.raw_response == tcp_result.raw_response


def test_send_query_ignores_unrelated_transaction_id():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        (
            make_response(transaction_id=0x5678),
            ("192.0.2.1", 53),
        ),
        (
            make_response(transaction_id=0x1234),
            ("192.0.2.1", 53),
        ),
    ]

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.raw_response == make_response()


def test_send_query_rejects_unexpected_server():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(),
        ("192.0.2.2", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(ServerUnreachableError):
            UDPTransport().send_query(
                SERVER,
                QUERY,
                TransportConfig(max_retries=0),
            )


def test_send_query_rejects_short_response():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        b"\x12\x34\x80\x00",
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(TransportError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_rejects_non_response_packet():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(TransportError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_times_out():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = TimeoutError

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(DNSTimeoutError):
            UDPTransport().send_query(
                SERVER,
                QUERY,
                TransportConfig(max_retries=0),
            )


def test_send_query_uses_configured_timeout():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(),
        ("192.0.2.1", 53),
    )

    config = TransportConfig(timeout_seconds=5.0)

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        UDPTransport().send_query(
            SERVER,
            QUERY,
            config,
        )

    fake_socket.settimeout.assert_called_once_with(5.0)


def test_send_query_with_fallback_uses_next_server():
    first_server = ServerAddress("192.0.2.1")
    second_server = ServerAddress("192.0.2.2")

    transport = UDPTransport()

    with patch.object(
        transport,
        "send_query",
        side_effect=[
            ServerUnreachableError("first server failed"),
            "success",
        ],
    ):
        result = transport.send_query_with_fallback(
            [first_server, second_server],
            QUERY,
        )

    assert result == "success"

def test_send_query_with_fallback_rejects_empty_servers():
    with pytest.raises(ServerUnreachableError):
        UDPTransport().send_query_with_fallback(
            [],
            QUERY,
        )


def test_send_query_with_fallback_raises_when_all_servers_fail():
    first_server = ServerAddress("192.0.2.1")
    second_server = ServerAddress("192.0.2.2")

    transport = UDPTransport()

    with patch.object(
        transport,
        "send_query",
        side_effect=ServerUnreachableError("server failed"),
    ):
        with pytest.raises(ServerUnreachableError):
            transport.send_query_with_fallback(
                [first_server, second_server],
                QUERY,
            )


def test_send_query_preserves_tcp_fallback_disabled_behavior():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(tc=True),
        ("192.0.2.1", 53),
    )

    config = TransportConfig(enable_tcp_fallback=False)

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(
            SERVER,
            QUERY,
            config,
        )

    assert result.tc_bit_set is True
    assert result.is_tcp is False