"""
DNS Internal Data Model Subsystem.

Owner: Avidipta
Phase: Phase 1
Responsibilities:
- DNS Header, Question, ResourceRecord representations
- Record types: A, AAAA, NS, CNAME, MX, TXT, SOA
- RDATA data structures and representations
- Implements data structures used by contracts and codec
"""
from .name import DNSName

from .header import DNSHeader

from .question import (
    DNSQuestion,
    QTYPE_CODES,
    QCLASS_CODES,
)

from .records import (
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)

from .message import (
    DNSMessage,
    DNSRecord,
)


__all__ = [
    "DNSName",

    "DNSHeader",

    "DNSQuestion",
    "QTYPE_CODES",
    "QCLASS_CODES",

    "ARecord",
    "AAAARecord",
    "NSRecord",
    "CNAMERecord",
    "MXRecord",
    "TXTRecord",
    "SOARecord",

    "DNSMessage",
    "DNSRecord",
]