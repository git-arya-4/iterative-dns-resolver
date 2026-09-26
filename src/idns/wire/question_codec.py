"""
DNS Question wire codec.

Owner: Avidipta
Phase: Phase 2
Task: 2.4

Encodes and decodes DNS Question sections.

DNS Question wire format:

    QNAME   variable length
    QTYPE   2 bytes
    QCLASS  2 bytes
"""

from __future__ import annotations

from idns.model import DNSName, DNSQuestion
from idns.wire.cursor import ByteCursor, DNSBoundsError
from idns.wire.name_codec import (
    DNSNameCodec,
    DNSNameCodecError,
)


class DNSQuestionCodecError(Exception):
    """Base exception for DNS question codec errors."""


class DNSQuestionEncodeError(DNSQuestionCodecError):
    """Raised when a DNS question cannot be encoded."""


class DNSQuestionDecodeError(DNSQuestionCodecError):
    """Raised when a DNS question cannot be decoded."""


class DNSQuestionCodec:
    """Encode and decode DNS Question sections."""

    @classmethod
    def encode(cls, question: DNSQuestion) -> bytes:
        """
        Encode a DNSQuestion into DNS wire-format bytes.

        Format:

            QNAME + QTYPE + QCLASS
        """

        if not isinstance(question, DNSQuestion):
            raise DNSQuestionEncodeError(
                "question must be an instance of DNSQuestion"
            )

        try:
            # ------------------------------------------------
            # QNAME
            # ------------------------------------------------
            encoded_name = DNSNameCodec.encode(
                question.qname
            )

            # ------------------------------------------------
            # QTYPE
            # ------------------------------------------------
            qtype = int(question.qtype_code)

            if not 0 <= qtype <= 0xFFFF:
                raise DNSQuestionEncodeError(
                    "QTYPE must fit in 16 bits"
                )

            # ------------------------------------------------
            # QCLASS
            # ------------------------------------------------
            qclass = int(question.qclass_code)

            if not 0 <= qclass <= 0xFFFF:
                raise DNSQuestionEncodeError(
                    "QCLASS must fit in 16 bits"
                )

            return (
                encoded_name
                + qtype.to_bytes(2, "big")
                + qclass.to_bytes(2, "big")
            )

        except DNSQuestionCodecError:
            raise

        except DNSNameCodecError as exc:
            raise DNSQuestionEncodeError(
                f"invalid QNAME: {exc}"
            ) from exc

        except (
            AttributeError,
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise DNSQuestionEncodeError(
                f"invalid DNS question: {exc}"
            ) from exc

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> DNSQuestion:
        """
        Decode a DNS Question from a ByteCursor.

        Reads:

            QNAME
            QTYPE
            QCLASS
        """

        if not isinstance(cursor, ByteCursor):
            raise DNSQuestionDecodeError(
                "cursor must be a ByteCursor"
            )

        try:
            # ------------------------------------------------
            # QNAME
            # ------------------------------------------------
            qname = DNSNameCodec.decode(cursor)

            # ------------------------------------------------
            # QTYPE
            # ------------------------------------------------
            qtype_code = cursor.read_u16()

            # ------------------------------------------------
            # QCLASS
            # ------------------------------------------------
            qclass_code = cursor.read_u16()

        except DNSBoundsError as exc:
            raise DNSQuestionDecodeError(
                "truncated DNS question"
            ) from exc

        except DNSNameCodecError as exc:
            raise DNSQuestionDecodeError(
                f"invalid QNAME: {exc}"
            ) from exc

        # DNSQuestion expects the textual type/class names.
        qtype = cls._qtype_name(qtype_code)
        qclass = cls._qclass_name(qclass_code)

        try:
            return DNSQuestion(
                qname=qname,
                qtype=qtype,
                qclass=qclass,
            )

        except (
            AttributeError,
            TypeError,
            ValueError,
        ) as exc:
            raise DNSQuestionDecodeError(
                f"invalid DNS question fields: {exc}"
            ) from exc

    @staticmethod
    def _qtype_name(code: int) -> str:
        """
        Convert a QTYPE numeric code into the name expected
        by DNSQuestion.

        Supported types are taken from the existing DNSQuestion
        model.
        """

        mapping = {
            1: "A",
            28: "AAAA",
            2: "NS",
            5: "CNAME",
            15: "MX",
            16: "TXT",
            6: "SOA",
        }

        try:
            return mapping[code]
        except KeyError as exc:
            raise DNSQuestionDecodeError(
                f"unsupported QTYPE code: {code}"
            ) from exc

    @staticmethod
    def _qclass_name(code: int) -> str:
        """
        Convert a QCLASS numeric code into the name expected
        by DNSQuestion.
        """

        mapping = {
            1: "IN",
        }

        try:
            return mapping[code]
        except KeyError as exc:
            raise DNSQuestionDecodeError(
                f"unsupported QCLASS code: {code}"
            ) from exc