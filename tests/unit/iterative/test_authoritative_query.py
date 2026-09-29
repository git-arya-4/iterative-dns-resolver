from unittest.mock import MagicMock

from idns.contracts.transport import ServerAddress, TransportResult
from idns.iterative.authoritative_query import AuthoritativeQuery
from idns.model import DNSHeader, DNSMessage


def test_authoritative_query_sends_query_to_server():
    transport = MagicMock()

    transport.send_query.return_value = TransportResult(
        raw_response=b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01",
        server_used=ServerAddress(
            "192.0.2.53",
            name="ns1.example.com",
        ),
        rtt_ms=1.0,
    )

    query = AuthoritativeQuery(transport)

    response, result = query.query(
        ServerAddress(
            "192.0.2.53",
            name="ns1.example.com",
        ),
        "example.com",
        record_type="A",
        transaction_id=0x1234,
    )

    assert response.header.transaction_id == 0x1234
    assert result.server_used.ip == "192.0.2.53"

    transport.send_query.assert_called_once()

    server = transport.send_query.call_args.args[0]

    assert server == ServerAddress(
        "192.0.2.53",
        name="ns1.example.com",
    )


def test_authoritative_query_supports_requested_record_type():
    transport = MagicMock()

    transport.send_query.return_value = TransportResult(
        raw_response=b"\x12\x34\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        server_used=ServerAddress("192.0.2.53"),
        rtt_ms=1.0,
    )

    query = AuthoritativeQuery(transport)

    query.query(
        ServerAddress("192.0.2.53"),
        "example.com",
        record_type="AAAA",
    )

    query_bytes = transport.send_query.call_args.args[1]

    assert query_bytes[0:2] == b"\x12\x34"


def test_authoritative_query_returns_decoded_dns_message():
    transport = MagicMock()

    transport.send_query.return_value = TransportResult(
        raw_response=b"\x12\x34\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        server_used=ServerAddress("192.0.2.53"),
        rtt_ms=1.0,
    )

    query = AuthoritativeQuery(transport)

    response, _ = query.query(
        ServerAddress("192.0.2.53"),
        "example.com",
    )

    assert isinstance(response, DNSMessage)
    assert response.header.transaction_id == 0x1234