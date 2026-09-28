import socket
from unittest.mock import MagicMock, call, patch

import pytest

from idns.contracts.transport import (
    ServerAddress,
    TransportConfig,
)
from idns.errors import (
    ServerUnreachableError,
    TransportError,
)
from idns.transport.udp import UDPTransport


SERVER = ServerAddress("192.0.2.1")
ALTERNATE_SERVER = ServerAddress("192.0.2.2")

QUERY = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def make_response(
    transaction_id: int = 0x1234,
    *,
    qr: bool = True,
    tc: bool = False,
) -> bytes:
    """Build a minimal DNS response header."""

    flags = 0

    if qr:
        flags |= 0x8000

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
    assert result.rtt_ms >= 0
    assert result.tc_bit_set is False

    fake_socket.sendto.assert_called_once_with(
        QUERY,
        ("192.0.2.1", 53),
    )


def test_send_query_sets_tcp_fallback_flag_when_tc_is_set():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(tc=True),
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.tc_bit_set is True


def test_send_query_rejects_response_from_wrong_server():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(),
        ("192.0.2.2", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(ServerUnreachableError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_ignores_mismatched_transaction_id():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        (
            make_response(transaction_id=0x5678),
            ("192.0.2.1", 53),
        ),
        (
            make_response(),
            ("192.0.2.1", 53),
        ),
    ]

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.raw_response == make_response()
    assert result.server_used == SERVER
    assert result.rtt_ms >= 0
    assert result.tc_bit_set is False

    assert fake_socket.recvfrom.call_count == 2


def test_send_query_rejects_non_response_packet():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(qr=False),
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(TransportError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_rejects_short_response():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        b"\x12\x34",
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(TransportError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_rejects_truncated_dns_header():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        b"\x12\x34\x80\x00",
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(TransportError):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_retries_after_timeout():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        socket.timeout,
        (
            make_response(),
            ("192.0.2.1", 53),
        ),
    ]

    config = TransportConfig(
        timeout_seconds=0.1,
        max_retries=1,
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(
            SERVER,
            QUERY,
            config,
        )

    assert result.raw_response == make_response()
    assert result.server_used == SERVER
    assert socket_mock.call_count == 2


def test_send_query_with_fallback_uses_alternate_server():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        socket.timeout,
        (
            make_response(),
            ("192.0.2.2", 53),
        ),
    ]

    config = TransportConfig(
        timeout_seconds=0.1,
        max_retries=0,
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query_with_fallback(
            [SERVER, ALTERNATE_SERVER],
            QUERY,
            config,
        )

    assert result.server_used == ALTERNATE_SERVER
    assert socket_mock.call_count == 2

    assert fake_socket.sendto.call_args_list == [
        call(QUERY, ("192.0.2.1", 53)),
        call(QUERY, ("192.0.2.2", 53)),
    ]


def test_send_query_with_fallback_retries_before_alternate_server():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        socket.timeout,
        socket.timeout,
        socket.timeout,
        (
            make_response(),
            ("192.0.2.2", 53),
        ),
    ]

    config = TransportConfig(
        timeout_seconds=0.1,
        max_retries=2,
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query_with_fallback(
            [SERVER, ALTERNATE_SERVER],
            QUERY,
            config,
        )

    assert result.server_used == ALTERNATE_SERVER
    assert socket_mock.call_count == 4

    assert fake_socket.sendto.call_args_list == [
        call(QUERY, ("192.0.2.1", 53)),
        call(QUERY, ("192.0.2.1", 53)),
        call(QUERY, ("192.0.2.1", 53)),
        call(QUERY, ("192.0.2.2", 53)),
    ]


def test_send_query_with_fallback_raises_when_all_servers_fail():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = [
        socket.timeout,
        socket.timeout,
        socket.timeout,
        socket.timeout,
    ]

    config = TransportConfig(
        timeout_seconds=0.1,
        max_retries=1,
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(ServerUnreachableError):
            UDPTransport().send_query_with_fallback(
                [SERVER, ALTERNATE_SERVER],
                QUERY,
                config,
            )

    assert socket_mock.call_count == 4


def test_send_query_with_fallback_rejects_empty_server_list():
    transport = UDPTransport()

    with pytest.raises(ServerUnreachableError):
        transport.send_query_with_fallback(
            [],
            QUERY,
        )