from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.transport import ServerAddress, TransportConfig
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.transport.udp import UDPTransport


QUERY = b"dns-query"
SERVER = ServerAddress("192.0.2.1")


def test_send_query_returns_response():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (
        b"dns-response",
        ("192.0.2.1", 53),
    )

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.raw_response == b"dns-response"
    assert result.server_used == SERVER
    assert result.rtt_ms >= 0

    fake_socket.settimeout.assert_called_once_with(2.0)
    fake_socket.sendto.assert_called_once_with(
        QUERY,
        ("192.0.2.1", 53),
    )


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

    # 1 initial attempt + 3 retries = 4 total attempts.
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
        b"dns-response",
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