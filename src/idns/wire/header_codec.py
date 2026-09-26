"""
DNS Header wire codec.

Owner: Avidipta
Phase: Phase 2
Task: 2.3

Implements encoding and decoding of the 12-byte DNS header
defined by RFC 1035.
"""

from __future__ import annotations

from idns.model import DNSHeader
from idns.wire.cursor import ByteCursor, DNSBoundsError


class DNSHeaderCodecError(Exception):
    """Base exception for DNS header codec errors."""


class DNSHeaderEncodeError(DNSHeaderCodecError):
    """Raised when a DNS header cannot be encoded."""


class DNSHeaderDecodeError(DNSHeaderCodecError):
    """Raised when a DNS header cannot be decoded."""


class DNSHeaderCodec:
    """Encode and decode DNS headers."""

    HEADER_SIZE = 12

    @classmethod
    def encode(cls, header: DNSHeader) -> bytes:
        """
        Encode a DNSHeader into the 12-byte DNS wire representation.
        """

        if not isinstance(header, DNSHeader):
            raise DNSHeaderEncodeError(
                "header must be an instance of DNSHeader"
            )

        try:
            flags = cls._encode_flags(header)

            result = bytearray()

            result.extend(
                int(header.transaction_id).to_bytes(2, "big")
            )

            result.extend(
                flags.to_bytes(2, "big")
            )

            result.extend(
                int(header.qdcount).to_bytes(2, "big")
            )

            result.extend(
                int(header.ancount).to_bytes(2, "big")
            )

            result.extend(
                int(header.nscount).to_bytes(2, "big")
            )

            result.extend(
                int(header.arcount).to_bytes(2, "big")
            )

            if len(result) != cls.HEADER_SIZE:
                raise DNSHeaderEncodeError(
                    "DNS header must be exactly 12 bytes"
                )

            return bytes(result)

        except DNSHeaderCodecError:
            raise

        except (AttributeError, TypeError, ValueError, OverflowError) as exc:
            raise DNSHeaderEncodeError(
                f"invalid DNS header: {exc}"
            ) from exc

    @classmethod
    def decode(cls, cursor: ByteCursor) -> DNSHeader:
        """
        Decode a 12-byte DNS header from a ByteCursor.
        """

        if not isinstance(cursor, ByteCursor):
            raise DNSHeaderDecodeError(
                "cursor must be a ByteCursor"
            )

        if cursor.remaining() < cls.HEADER_SIZE:
            raise DNSHeaderDecodeError(
                "DNS header requires 12 bytes"
            )

        try:
            transaction_id = cursor.read_u16()
            flags = cursor.read_u16()

            qdcount = cursor.read_u16()
            ancount = cursor.read_u16()
            nscount = cursor.read_u16()
            arcount = cursor.read_u16()

        except DNSBoundsError as exc:
            raise DNSHeaderDecodeError(
                "truncated DNS header"
            ) from exc

        return DNSHeader(
            transaction_id=transaction_id,

            qr=(flags >> 15) & 0x01,
            opcode=(flags >> 11) & 0x0F,
            aa=(flags >> 10) & 0x01,
            tc=(flags >> 9) & 0x01,
            rd=(flags >> 8) & 0x01,
            ra=(flags >> 7) & 0x01,

            # RFC 1035 reserves these three bits.
            z=(flags >> 4) & 0x07,

            rcode=flags & 0x0F,

            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
        )

    @staticmethod
    def _encode_flags(header: DNSHeader) -> int:
        """Pack DNS header flags into a 16-bit integer."""

        qr = int(header.qr)
        opcode = int(header.opcode)
        aa = int(header.aa)
        tc = int(header.tc)
        rd = int(header.rd)
        ra = int(header.ra)
        z = int(header.z)
        rcode = int(header.rcode)

        if qr not in (0, 1):
            raise DNSHeaderEncodeError(
                "qr must be 0 or 1"
            )

        if not 0 <= opcode <= 15:
            raise DNSHeaderEncodeError(
                "opcode must fit in 4 bits"
            )

        for name, value in (
            ("aa", aa),
            ("tc", tc),
            ("rd", rd),
            ("ra", ra),
        ):
            if value not in (0, 1):
                raise DNSHeaderEncodeError(
                    f"{name} must be 0 or 1"
                )

        if not 0 <= z <= 7:
            raise DNSHeaderEncodeError(
                "z must fit in 3 bits"
            )

        if not 0 <= rcode <= 15:
            raise DNSHeaderEncodeError(
                "rcode must fit in 4 bits"
            )

        flags = 0

        flags |= qr << 15
        flags |= opcode << 11
        flags |= aa << 10
        flags |= tc << 9
        flags |= rd << 8
        flags |= ra << 7
        flags |= z << 4
        flags |= rcode

        return flags