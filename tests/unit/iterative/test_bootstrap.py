from unittest.mock import MagicMock

from idns.contracts.transport import (
    ServerAddress,
    TransportResult,
)
from idns.iterative.bootstrap import NameserverBootstrap
from idns.model import (
    ARecord,
    AAAARecord,
    DNSHeader,
    DNSMessage,
    DNSName,
    NSRecord,
)
from idns.wire.message_encoder import DNSMessageEncoder


def test_bootstrap_resolves_nameserver_address_with_callback():
    nameserver = DNSName("ns1.example.com")

    def resolve_address(name: DNSName) -> list[str]:
        assert name == nameserver
        return ["192.0.2.10"]

    bootstrap = NameserverBootstrap(
        resolve_address=resolve_address,
    )

    addresses = bootstrap.resolve(nameserver)

    assert addresses == ["192.0.2.10"]


def test_bootstrap_supports_multiple_addresses():
    nameserver = DNSName("ns1.example.com")

    bootstrap = NameserverBootstrap(
        resolve_address=lambda name: [
            "192.0.2.10",
            "2001:db8::10",
        ],
    )

    addresses = bootstrap.resolve(nameserver)

    assert addresses == [
        "192.0.2.10",
        "2001:db8::10",
    ]


def test_bootstrap_returns_empty_when_no_address_is_found():
    bootstrap = NameserverBootstrap(
        resolve_address=lambda name: [],
    )

    addresses = bootstrap.resolve(
        DNSName("ns1.example.com")
    )

    assert addresses == []


def test_bootstrap_requires_transport_for_default_resolution():
    bootstrap = NameserverBootstrap()

    try:
        bootstrap.resolve(DNSName("ns1.example.com"))
    except ValueError as exc:
        assert "DNS transport" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError when no DNS transport is provided."
        )


def test_bootstrap_requires_root_servers_for_default_resolution():
    transport = MagicMock()

    bootstrap = NameserverBootstrap(
        transport=transport,
    )

    try:
        bootstrap.resolve(DNSName("ns1.example.com"))
    except ValueError as exc:
        assert "root server hints" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError when root hints are missing."
        )


def test_bootstrap_extracts_matching_addresses():
    nameserver = DNSName("ns1.example.com")

    records = [
        ARecord(
            name=nameserver,
            address="192.0.2.10",
            ttl=300,
        ),
        ARecord(
            name=DNSName("other.example.com"),
            address="192.0.2.20",
            ttl=300,
        ),
    ]

    addresses = NameserverBootstrap._extract_addresses(
        records,
        nameserver,
    )

    assert addresses == ["192.0.2.10"]


def test_bootstrap_deduplicates_addresses():
    nameserver = DNSName("ns1.example.com")

    records = [
        ARecord(
            name=nameserver,
            address="192.0.2.10",
            ttl=300,
        ),
        ARecord(
            name=nameserver,
            address="192.0.2.10",
            ttl=100,
        ),
    ]

    addresses = NameserverBootstrap._extract_addresses(
        records,
        nameserver,
    )

    assert addresses == ["192.0.2.10"]


class FakeTransport:
    """Return predetermined DNS responses for bootstrap tests."""

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

        return TransportResult(
            raw_response=self.responses.pop(0),
            server_used=servers[0],
            rtt_ms=1.0,
        )

    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config=None,
    ) -> TransportResult:
        self.queries.append(([server], query_bytes))

        return TransportResult(
            raw_response=self.responses.pop(0),
            server_used=server,
            rtt_ms=1.0,
        )
def test_bootstrap_uses_iterative_dns_and_glue():
    nameserver = DNSName("ns1.example.com")

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
                nameserver=nameserver,
                ttl=86400,
            )
        ],
        additionals=[
            ARecord(
                name=nameserver,
                address="192.0.2.10",
                ttl=86400,
            )
        ],
    )

    authoritative_response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        answers=[
            ARecord(
                name=nameserver,
                address="192.0.2.10",
                ttl=300,
            )
        ],
    )

    transport = FakeTransport(
        [
            DNSMessageEncoder.encode(root_response),
            DNSMessageEncoder.encode(tld_response),
            DNSMessageEncoder.encode(authoritative_response),
        ]
    )

    bootstrap = NameserverBootstrap(
        root_servers=[
            {
                "name": "a.root-servers.net",
                "ipv4": "198.41.0.4",
            }
        ],
        transport=transport,
    )

    addresses = bootstrap._resolve_iteratively(
        nameserver,
        "A",
    )

    assert addresses == ["192.0.2.10"]

    assert len(transport.queries) == 3

def test_bootstrap_extracts_aaaa_addresses():
    nameserver = DNSName("ns1.example.com")

    records = [
        AAAARecord(
            name=nameserver,
            address="2001:db8::10",
            ttl=300,
        ),
    ]

    addresses = NameserverBootstrap._extract_addresses(
        records,
        nameserver,
    )

    assert addresses == ["2001:db8::10"]


def test_bootstrap_continues_after_referral_when_target_has_no_glue():
    nameserver = DNSName("ns1.example.net")
    helper_nameserver = DNSName("ns2.example.net")

    root_response_a = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("net"),
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

    tld_response_a = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("example.net"),
                nameserver=nameserver,
                ttl=86400,
            ),
            NSRecord(
                name=DNSName("example.net"),
                nameserver=helper_nameserver,
                ttl=86400,
            ),
        ],
        additionals=[
            ARecord(
                name=helper_nameserver,
                address="192.0.2.54",
                ttl=86400,
            )
        ],
    )

    authoritative_response_a = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        answers=[
            ARecord(
                name=nameserver,
                address="192.0.2.10",
                ttl=300,
            )
        ],
    )

    root_response_aaaa = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("net"),
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

    tld_response_aaaa = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("example.net"),
                nameserver=nameserver,
                ttl=86400,
            ),
            NSRecord(
                name=DNSName("example.net"),
                nameserver=helper_nameserver,
                ttl=86400,
            ),
        ],
        additionals=[
            ARecord(
                name=helper_nameserver,
                address="192.0.2.54",
                ttl=86400,
            )
        ],
    )

    authoritative_response_aaaa = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        answers=[
            AAAARecord(
                name=nameserver,
                address="2001:db8::10",
                ttl=300,
            )
        ],
    )

    transport = FakeTransport(
        [
            DNSMessageEncoder.encode(root_response_a),
            DNSMessageEncoder.encode(tld_response_a),
            DNSMessageEncoder.encode(authoritative_response_a),
            DNSMessageEncoder.encode(root_response_aaaa),
            DNSMessageEncoder.encode(tld_response_aaaa),
            DNSMessageEncoder.encode(authoritative_response_aaaa),
        ]
    )

    bootstrap = NameserverBootstrap(
        root_servers=[
            {
                "name": "a.root-servers.net",
                "ipv4": "198.41.0.4",
            }
        ],
        transport=transport,
    )

    addresses = bootstrap.resolve(nameserver)

    assert addresses == [
        "192.0.2.10",
        "2001:db8::10",
    ]

    assert len(transport.queries) == 6

    assert transport.queries[2][0][0].ip == "192.0.2.54"
    assert transport.queries[5][0][0].ip == "192.0.2.54"