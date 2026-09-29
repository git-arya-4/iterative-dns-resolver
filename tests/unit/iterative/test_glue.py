from idns.iterative.glue import GlueExtractor
from idns.model import (
    ARecord,
    AAAARecord,
    DNSHeader,
    DNSMessage,
    DNSName,
    NSRecord,
)


def test_extracts_a_and_aaaa_glue_for_selected_nameservers():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            ),
        ],
        additionals=[
            ARecord(
                name=DNSName("a.gtld-servers.net"),
                address="192.0.2.1",
                ttl=86400,
            ),
            AAAARecord(
                name=DNSName("a.gtld-servers.net"),
                address="2001:db8::1",
                ttl=86400,
            ),
        ],
    )

    glue = GlueExtractor.extract(
        response,
        [DNSName("a.gtld-servers.net")],
    )

    assert glue == {
        DNSName("a.gtld-servers.net"): [
            "192.0.2.1",
            "2001:db8::1",
        ]
    }


def test_ignores_additional_records_for_unselected_nameservers():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        additionals=[
            ARecord(
                name=DNSName("a.gtld-servers.net"),
                address="192.0.2.1",
                ttl=86400,
            ),
            ARecord(
                name=DNSName("other.example"),
                address="192.0.2.2",
                ttl=86400,
            ),
        ],
    )

    glue = GlueExtractor.extract(
        response,
        [DNSName("a.gtld-servers.net")],
    )

    assert glue == {
        DNSName("a.gtld-servers.net"): ["192.0.2.1"],
    }


def test_returns_empty_when_no_glue_records_exist():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        additionals=[],
    )

    glue = GlueExtractor.extract(
        response,
        [DNSName("a.gtld-servers.net")],
    )

    assert glue == {}