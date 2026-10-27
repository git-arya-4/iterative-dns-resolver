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


@dataclass(frozen=True)
class EDNSOption:
    """An EDNS option retained as its wire-format code and payload."""

    code: int
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.code, int) or not 0 <= self.code <= 0xFFFF:
            raise ValueError("EDNS option code must be between 0 and 65535")
        if not isinstance(self.data, bytes):
            raise ValueError("EDNS option data must be bytes")
        if len(self.data) > 0xFFFF:
            raise ValueError("EDNS option data is too large")


@dataclass(frozen=True)
class OPTRecord:
    """EDNS(0) OPT pseudo-record; valid only in the additional section."""

    name: DNSName
    udp_payload_size: int
    version: int = 0
    flags: int = 0
    options: tuple[EDNSOption, ...] = ()
    extended_rcode: int = 0
    record_type: str = "OPT"
    record_class: str = "EDNS"

    def __post_init__(self) -> None:
        if self.name != DNSName("."):
            raise ValueError("OPT owner name must be the root name")
        if not 0 <= self.udp_payload_size <= 0xFFFF:
            raise ValueError("UDP payload size must be between 0 and 65535")
        if not 0 <= self.version <= 0xFF:
            raise ValueError("EDNS version must be between 0 and 255")
        if not 0 <= self.flags <= 0xFFFF:
            raise ValueError("EDNS flags must be between 0 and 65535")
        if not 0 <= self.extended_rcode <= 0xFF:
            raise ValueError("extended RCODE must be between 0 and 255")
        if not isinstance(self.options, tuple):
            raise ValueError("EDNS options must be a tuple")
        if not all(isinstance(option, EDNSOption) for option in self.options):
            raise ValueError("EDNS options must contain EDNSOption values")

    @property
    def dnssec_ok(self) -> bool:
        return bool(self.flags & 0x8000)


@dataclass(frozen=True)
class DNSKEYRecord:
    """DNSSEC public key record (RFC 4034)."""

    name: DNSName
    flags: int
    protocol: int
    algorithm: int
    public_key: bytes
    ttl: int

    record_type: str = "DNSKEY"
    record_class: str = "IN"


@dataclass(frozen=True)
class RRSIGRecord:
    """DNSSEC resource-record-set signature (RFC 4034)."""

    name: DNSName
    type_covered: str
    algorithm: int
    labels: int
    original_ttl: int
    signature_expiration: int
    signature_inception: int
    key_tag: int
    signer_name: DNSName
    signature: bytes
    ttl: int

    record_type: str = "RRSIG"
    record_class: str = "IN"


@dataclass(frozen=True)
class DSRecord:
    """Delegation signer digest record (RFC 4034)."""

    name: DNSName
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes
    ttl: int

    record_type: str = "DS"
    record_class: str = "IN"
