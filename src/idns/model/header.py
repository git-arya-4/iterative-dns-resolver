from dataclasses import dataclass


@dataclass
class DNSHeader:
    """
    DNS message header model.

    Byte-level encoding/decoding belongs
    to the later wire-layer tasks.
    """

    transaction_id: int

    # Flags
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 0
    ra: int = 0
    z: int = 0
    rcode: int = 0

    # Section counts
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def __post_init__(self):

        if not 0 <= self.transaction_id <= 0xFFFF:
            raise ValueError(
                "transaction_id must be between 0 and 65535"
            )

        if self.qr not in (0, 1):
            raise ValueError("qr must be 0 or 1")

        if not 0 <= self.opcode <= 15:
            raise ValueError(
                "opcode must be between 0 and 15"
            )

        if self.aa not in (0, 1):
            raise ValueError("aa must be 0 or 1")

        if self.tc not in (0, 1):
            raise ValueError("tc must be 0 or 1")

        if self.rd not in (0, 1):
            raise ValueError("rd must be 0 or 1")

        if self.ra not in (0, 1):
            raise ValueError("ra must be 0 or 1")

        if not 0 <= self.z <= 7:
            raise ValueError("z must be between 0 and 7")

        if not 0 <= self.rcode <= 15:
            raise ValueError(
                "rcode must be between 0 and 15"
            )

        for field_name in (
            "qdcount",
            "ancount",
            "nscount",
            "arcount",
        ):
            value = getattr(self, field_name)

            if not 0 <= value <= 0xFFFF:
                raise ValueError(
                    f"{field_name} must be between 0 and 65535"
                )