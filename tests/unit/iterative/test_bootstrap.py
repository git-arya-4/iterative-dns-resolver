from unittest.mock import MagicMock

from idns.iterative.bootstrap import NameserverBootstrap
from idns.model import ARecord, DNSName


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