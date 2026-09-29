from idns.iterative.referral import ReferralParser
from idns.model import DNSHeader, DNSMessage, DNSName, NSRecord


def test_select_nameservers_for_delegated_zone():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            ),
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("b.gtld-servers.net"),
                ttl=86400,
            ),
        ],
    )

    nameservers = ReferralParser.select_nameservers(
        response,
        "com",
    )

    assert nameservers == [
        DNSName("a.gtld-servers.net"),
        DNSName("b.gtld-servers.net"),
    ]


def test_select_nameservers_ignores_other_zones():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[
            NSRecord(
                name=DNSName("com"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            ),
            NSRecord(
                name=DNSName("net"),
                nameserver=DNSName("a.gtld-servers.net"),
                ttl=86400,
            ),
        ],
    )

    nameservers = ReferralParser.select_nameservers(
        response,
        "com",
    )

    assert nameservers == [
        DNSName("a.gtld-servers.net"),
    ]


def test_select_nameservers_returns_empty_when_no_matching_referral():
    response = DNSMessage(
        header=DNSHeader(transaction_id=0x1234),
        authorities=[],
    )

    nameservers = ReferralParser.select_nameservers(
        response,
        "com",
    )

    assert nameservers == []