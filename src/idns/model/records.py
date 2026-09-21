from dataclasses import dataclass

from .name import DNSName


@dataclass(frozen=True)
class ARecord:
    """
    IPv4 address record.
    """

    name: DNSName
    address: str
    ttl: int

    record_type: str = "A"
    record_class: str = "IN"


@dataclass(frozen=True)
class AAAARecord:
    """
    IPv6 address record.
    """

    name: DNSName
    address: str
    ttl: int

    record_type: str = "AAAA"
    record_class: str = "IN"


@dataclass(frozen=True)
class NSRecord:
    """
    Authoritative name server record.
    """

    name: DNSName
    nameserver: DNSName
    ttl: int

    record_type: str = "NS"
    record_class: str = "IN"


@dataclass(frozen=True)
class CNAMERecord:
    """
    Canonical-name alias record.
    """

    name: DNSName
    canonical_name: DNSName
    ttl: int

    record_type: str = "CNAME"
    record_class: str = "IN"


@dataclass(frozen=True)
class MXRecord:
    """
    Mail-exchange record.
    """

    name: DNSName
    preference: int
    exchange: DNSName
    ttl: int

    record_type: str = "MX"
    record_class: str = "IN"


@dataclass(frozen=True)
class TXTRecord:
    """
    Text record.

    TXT records can contain multiple
    character strings.
    """

    name: DNSName
    text: tuple[str, ...]
    ttl: int

    record_type: str = "TXT"
    record_class: str = "IN"


@dataclass(frozen=True)
class SOARecord:
    """
    Start of Authority record.
    """

    name: DNSName

    mname: DNSName
    rname: DNSName

    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    ttl: int

    record_type: str = "SOA"
    record_class: str = "IN"