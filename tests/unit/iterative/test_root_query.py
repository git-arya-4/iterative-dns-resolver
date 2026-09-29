from unittest.mock import MagicMock

from idns.contracts.transport import (
    ServerAddress,
    TransportResult,
)
from idns.iterative.root_query import RootQuery
from idns.model import DNSHeader, DNSMessage


ROOT_SERVERS = [
    {
        "name": "a.root-servers.net",
        "ipv4": "198.41.0.4",
    },
    {
        "name": "b.root-servers.net",
        "ipv4": "170.247.170.2",
    },
]


def test_root_query_builds_and_decodes_dns_query():
    transport = MagicMock()

    response = DNSMessage(
        header=DNSHeader(
            transaction_id=0x1234,
            qr=1,
        )
    )

    transport.send_query_with_fallback.return_value = TransportResult(
        raw_response=b"\x12\x34\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        server_used=ServerAddress(
            "198.41.0.4",
            name="a.root-servers.net",
        ),
        rtt_ms=1.0,
    )

    query = RootQuery(
        root_servers=ROOT_SERVERS,
        transport=transport,
    )

    # Replace the decoder result with our known DNSMessage.
    # The transport call itself is what this test primarily verifies.
    result, transport_result = query.query(
        "example.com",
        record_type="A",
        transaction_id=0x1234,
    )

    assert result.header.transaction_id == 0x1234
    assert transport_result.server_used.ip == "198.41.0.4"

    transport.send_query_with_fallback.assert_called_once()

    args = transport.send_query_with_fallback.call_args.args

    servers = args[0]
    query_bytes = args[1]

    assert servers == [
        ServerAddress(
            "198.41.0.4",
            port=53,
            protocol="UDP",
            name="a.root-servers.net",
        ),
        ServerAddress(
            "170.247.170.2",
            port=53,
            protocol="UDP",
            name="b.root-servers.net",
        ),
    ]

    assert query_bytes[0:2] == b"\x12\x34"