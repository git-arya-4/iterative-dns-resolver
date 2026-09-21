from dataclasses import dataclass, field
from typing import Union

from .header import DNSHeader
from .question import DNSQuestion

from .records import (
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)


DNSRecord = Union[
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
]


@dataclass
class DNSMessage:
    """
    Complete logical DNS message.

    A DNS message consists of:

        Header
        Questions
        Answers
        Authorities
        Additionals

    This class represents the structure only.

    Byte encoding/decoding will be implemented
    later in the wire layer.
    """

    header: DNSHeader

    questions: list[DNSQuestion] = field(
        default_factory=list
    )

    answers: list[DNSRecord] = field(
        default_factory=list
    )

    authorities: list[DNSRecord] = field(
        default_factory=list
    )

    additionals: list[DNSRecord] = field(
        default_factory=list
    )

    def update_counts(self) -> None:
        """
        Synchronize header section counts
        with the actual message contents.
        """

        self.header.qdcount = len(
            self.questions
        )

        self.header.ancount = len(
            self.answers
        )

        self.header.nscount = len(
            self.authorities
        )

        self.header.arcount = len(
            self.additionals
        )