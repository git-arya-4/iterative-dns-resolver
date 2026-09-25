from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.transport import ServerAddress, TransportConfig
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.transport.udp import UDPTransport


QUERY = b"dns-query"
SERVER = ServerAddress("8.8.8.8")


def test_send_query_returns_response():
    fake_socket = MagicMock()
    fake_socket.recvfrom.return_value = (b"dns-response", ("8.8.8.8", 53))

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        result = UDPTransport().send_query(SERVER, QUERY)

    assert result.raw_response == b"dns-response"
    assert result.server_used == SERVER
    assert result.rtt_ms >= 0

    fake_socket.settimeout.assert_called_once_with(2.0)
    fake_socket.sendto.assert_called_once_with(
        QUERY,
        ("8.8.8.8", 53),
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

    assert socket_mock.call_count == 3


def test_send_query_raises_unreachable_error():
    fake_socket = MagicMock()
    fake_socket.sendto.side_effect = OSError("network unavailable")

    with patch("idns.transport.udp.socket.socket") as socket_mock:
        socket_mock.return_value.__enter__.return_value = fake_socket

        with pytest.raises(ServerUnreachableError):
            UDPTransport().send_query(SERVER, QUERY)