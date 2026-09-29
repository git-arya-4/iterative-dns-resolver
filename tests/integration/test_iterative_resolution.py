from idns.contracts.transport import (
    ServerAddress,
    TransportResult,
)
from idns.iterative.root_query import RootQuery
from idns.iterative.tld_query import TLDQuery
from idns.model import (
    ARecord,
    DNSHeader,
    DNSMessage,
    DNSName,
    NSRecord,
)
from idns.wire.message_decoder import DNSMessageDecoder
from idns.wire.message_encoder import DNSMessageEncoder


class FakeTransport:
    """Return predetermined DNS responses for integration testing."""

    def __init__(self, responses: list[bytes]) -> None:
        self.responses = responses
        self.queries: list[tuple[list[ServerAddress], bytes]] = []

    def send_query_with_fallback(
        self,
        servers: list[ServerAddress],
        query_bytes: bytes,
        config=None,
    ) -> TransportResult:
        self.queries.append((servers, query_bytes))

        response = self.responses.pop(0)

        return TransportResult(
            raw_response=response,
            server_used=servers[0],
            rtt_ms=1.0,
        )


def test_root_to_tld_iterative_flow():
    root_response = DNSMessage(
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

    tld_response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("example.com"),
                nameserver=DNSName("ns1.example.com"),
                ttl=86400,
            )
        ],
        additionals=[
            ARecord(
                name=DNSName("ns1.example.com"),
                address="192.0.2.10",
                ttl=86400,
            )
        ],
    )

    root_response_bytes = DNSMessageEncoder.encode(root_response)
    tld_response_bytes = DNSMessageEncoder.encode(tld_response)

    transport = FakeTransport(
        [
            root_response_bytes,
            tld_response_bytes,
        ]
    )

    root_query = RootQuery(
        root_servers=[
            {
                "name": "a.root-servers.net",
                "ipv4": "198.41.0.4",
            }
        ],
        transport=transport,
    )

    root_result, _ = root_query.query(
        "example.com",
    )

    tld_query = TLDQuery(
        transport=transport,
    )

    tld_result, _ = tld_query.query(
        root_result,
        "example.com",
        "com",
    )

    assert tld_result.authorities[0].name == DNSName("example.com")
    assert (
        tld_result.authorities[0].nameserver
        == DNSName("ns1.example.com")
    )

    assert len(transport.queries) == 2

    root_servers_used = transport.queries[0][0]

    assert root_servers_used == [
        ServerAddress(
            ip="198.41.0.4",
            port=53,
            protocol="UDP",
            name="a.root-servers.net",
        )
    ]

    tld_servers_used = transport.queries[1][0]

    assert tld_servers_used == [
        ServerAddress(
            ip="192.0.2.53",
            port=53,
            protocol="UDP",
            name="a.gtld-servers.net",
        )
    ]

    root_query_message = DNSMessageDecoder.decode(
        transport.queries[0][1]
    )

    tld_query_message = DNSMessageDecoder.decode(
        transport.queries[1][1]
    )

    assert root_query_message.questions[0].qname == DNSName(
        "example.com"
    )

    assert tld_query_message.questions[0].qname == DNSName(
        "example.com"
    )