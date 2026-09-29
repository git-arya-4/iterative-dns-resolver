from unittest.mock import MagicMock

from idns.contracts.transport import ServerAddress, TransportResult
from idns.iterative.tld_query import TLDQuery
from idns.model import (
    DNSHeader,
    DNSMessage,
    DNSName,
    NSRecord,
)


def test_tld_query_follows_referral_using_glue():
    transport = MagicMock()

    transport.send_query_with_fallback.return_value = TransportResult(
        raw_response=b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01",
        server_used=ServerAddress(
            "192.0.2.1",
            name="a.gtld-servers.net",
        ),
        rtt_ms=1.0,
    )

    referral = DNSMessage(
        header=DNSHeader(transaction_id=0x1111),
        authorities=[
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            )
        ],
        additionals=[],
    )

    from idns.model import ARecord

    referral.additionals.append(
        ARecord(
            name=DNSName("a.gtld-servers.net"),
            address="192.0.2.1",
            ttl=86400,
        )
    )

    query = TLDQuery(transport)

    response, result = query.query(
        referral,
        "example.com",
        "com",
        transaction_id=0x1234,
    )

    assert response.header.transaction_id == 0x1234
    assert result.server_used.ip == "192.0.2.1"

    transport.send_query_with_fallback.assert_called_once()

    servers = transport.send_query_with_fallback.call_args.args[0]

    assert servers == [
        ServerAddress(
            "192.0.2.1",
            port=53,
            protocol="UDP",
            name="a.gtld-servers.net",
        )
    ]


def test_tld_query_raises_when_no_nameservers_are_found():
    transport = MagicMock()

    query = TLDQuery(transport)

    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
    )

    try:
        query.query(
            response,
            "example.com",
            "com",
        )
    except ValueError as exc:
        assert "No nameservers found" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_tld_query_raises_when_glue_is_missing():
    transport = MagicMock()

    query = TLDQuery(transport)

    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            )
        ],
    )

    try:
        query.query(
            response,
            "example.com",
            "com",
        )
    except ValueError as exc:
        assert "No nameserver addresses" in str(exc)
    else:
        raise AssertionError("Expected ValueError")