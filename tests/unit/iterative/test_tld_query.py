from unittest.mock import MagicMock

from idns.contracts.transport import ServerAddress, TransportResult
from idns.iterative.bootstrap import NameserverBootstrap
from idns.iterative.tld_query import TLDQuery
from idns.model import (
    ARecord,
    DNSHeader,
    DNSMessage,
    DNSName,
    NSRecord,
)
from idns.wire.message_decoder import DNSMessageDecoder


def test_tld_query_follows_referral_using_glue():
    transport = MagicMock()

    transport.send_query_with_fallback.return_value = TransportResult(
        raw_response=(
            b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        ),
        server_used=ServerAddress(
            "192.0.2.53",
            name="a.gtld-servers.net",
        ),
        rtt_ms=1.0,
    )

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
        additionals=[
            ARecord(
                name=DNSName("a.gtld-servers.net"),
                address="192.0.2.53",
                ttl=86400,
            )
        ],
    )

    _, result = query.query(
        response,
        "example.com",
        "com",
    )

    servers = (
        transport.send_query_with_fallback.call_args.args[0]
    )

    assert servers == [
        ServerAddress(
            "192.0.2.53",
            port=53,
            protocol="UDP",
            name="a.gtld-servers.net",
        )
    ]

    assert result.server_used.ip == "192.0.2.53"


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
        raise AssertionError(
            "Expected ValueError when no nameservers are found."
        )


def test_tld_query_raises_when_glue_and_bootstrap_are_missing():
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
        assert (
            "No nameserver addresses were available from glue "
            "or nameserver bootstrap"
        ) in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError when glue and bootstrap are missing."
        )


def test_tld_query_uses_requested_record_type():
    transport = MagicMock()

    transport.send_query_with_fallback.return_value = TransportResult(
        raw_response=(
            b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x1c\x00\x01"
        ),
        server_used=ServerAddress(
            "192.0.2.53",
            name="a.gtld-servers.net",
        ),
        rtt_ms=1.0,
    )

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
        additionals=[
            ARecord(
                name=DNSName("a.gtld-servers.net"),
                address="192.0.2.53",
                ttl=86400,
            )
        ],
    )

    query.query(
        response,
        "example.com",
        "com",
        record_type="AAAA",
    )

    query_bytes = (
        transport.send_query_with_fallback.call_args.args[1]
    )

    decoded_query = DNSMessageDecoder.decode(query_bytes)

    assert decoded_query.questions[0].qtype == "AAAA"


def test_tld_query_bootstraps_nameserver_when_glue_is_missing():
    transport = MagicMock()

    transport.send_query_with_fallback.return_value = TransportResult(
        raw_response=(
            b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        ),
        server_used=ServerAddress(
            "192.0.2.53",
            name="a.gtld-servers.net",
        ),
        rtt_ms=1.0,
    )

    bootstrap = MagicMock(spec=NameserverBootstrap)
    bootstrap.resolve.return_value = ["192.0.2.53"]

    query = TLDQuery(
        transport,
        bootstrap=bootstrap,
    )

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

    _, result = query.query(
        response,
        "example.com",
        "com",
    )

    bootstrap.resolve.assert_called_once_with(
        DNSName("a.gtld-servers.net")
    )

    servers = (
        transport.send_query_with_fallback.call_args.args[0]
    )

    assert servers == [
        ServerAddress(
            "192.0.2.53",
            port=53,
            protocol="UDP",
            name="a.gtld-servers.net",
        )
    ]

    assert result.server_used.ip == "192.0.2.53"