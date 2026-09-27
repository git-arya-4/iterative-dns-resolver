from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.transport import ServerAddress, TransportConfig
from idns.errors import DNSTimeoutError, ServerUnreachableError, TransportError
from idns.transport.udp import UDPTransport


QUERY = bytes.fromhex(
    "123401000001000000000000"
    "076578616d706c6503636f6d0000010001"
)

SERVER = ServerAddress("192.0.2.1")


def make_response(
    transaction_id: int = 0x1234,
    qr: int = 1,
    tc: int = 0,
) -> bytes:
    flags = (qr << 15) | (tc << 9)

    return (
        transaction_id.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def test_send_query_returns_matching_response():
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

    fake_socket.settimeout.assert_called_once_with(2.0)
    fake_socket.sendto.assert_called_once_with(
        QUERY,
        ("192.0.2.1", 53),
    )


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
        make_response(qr=0),
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(
            TransportError,
            match="response flag",
        ):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_sets_truncated_flag():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(tc=1),
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.tc_bit_set is True


def test_send_query_retries_after_timeout():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = TimeoutError

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        config = TransportConfig(
            timeout_seconds=0.1,
            max_retries=3,
        )

        with pytest.raises(DNSTimeoutError):
            UDPTransport().send_query(SERVER, QUERY, config)

    assert socket_mock.call_count == 4


def test_send_query_max_retries_zero_makes_one_attempt():
    fake_socket = MagicMock()
    fake_socket.recvfrom.side_effect = TimeoutError

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        config = TransportConfig(
            timeout_seconds=0.1,
            max_retries=0,
        )

        with pytest.raises(DNSTimeoutError):
            UDPTransport().send_query(SERVER, QUERY, config)

    assert socket_mock.call_count == 1


def test_send_query_rejects_unexpected_response_source():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        make_response(),
        ("192.0.2.2", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(
            ServerUnreachableError,
            match="unexpected server",
        ):
            UDPTransport().send_query(SERVER, QUERY)


def test_send_query_raises_unreachable_error():
    fake_socket = MagicMock()
    fake_socket.sendto.side_effect = OSError("network unavailable")

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(ServerUnreachableError):
            UDPTransport().send_query(SERVER, QUERY)
