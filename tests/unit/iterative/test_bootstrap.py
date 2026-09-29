from idns.iterative.bootstrap import NameserverBootstrap
from idns.model import DNSName


def test_bootstrap_resolves_nameserver_address():
    nameserver = DNSName("ns1.example.com")

    def resolve_address(name: DNSName) -> list[str]:
        assert name == nameserver
        return ["192.0.2.10"]

    bootstrap = NameserverBootstrap(resolve_address)

    addresses = bootstrap.resolve(nameserver)

    assert addresses == ["192.0.2.10"]


def test_bootstrap_supports_multiple_addresses():
    nameserver = DNSName("ns1.example.com")

    bootstrap = NameserverBootstrap(
        lambda name: [
            "192.0.2.10",
            "2001:db8::10",
        ]
    )

    addresses = bootstrap.resolve(nameserver)

    assert addresses == [
        "192.0.2.10",
        "2001:db8::10",
    ]


def test_bootstrap_returns_empty_when_no_address_is_found():
    bootstrap = NameserverBootstrap(
        lambda name: []
    )

    addresses = bootstrap.resolve(
        DNSName("ns1.example.com")
    )

    assert addresses == []