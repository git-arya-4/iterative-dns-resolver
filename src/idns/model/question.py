from dataclasses import dataclass

from .name import DNSName


QTYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


QCLASS_CODES = {
    "IN": 1,
}


@dataclass(frozen=True)
class DNSQuestion:
    """
    Represents one DNS question.

    Example:

        google.com
        A
        IN
    """

    qname: DNSName
    qtype: str = "A"
    qclass: str = "IN"

    def __post_init__(self):

        if self.qtype not in QTYPE_CODES:
            raise ValueError(
                f"Unsupported DNS question type: {self.qtype}"
            )

        if self.qclass not in QCLASS_CODES:
            raise ValueError(
                f"Unsupported DNS question class: {self.qclass}"
            )

    @property
    def qtype_code(self) -> int:
        return QTYPE_CODES[self.qtype]

    @property
    def qclass_code(self) -> int:
        return QCLASS_CODES[self.qclass]