"""
DNS Message Decoder.

Phase: Phase 3
Task: 3.6

Decodes a complete DNS message:

    Header
    Questions
    Answers
    Authority
    Additional

Supported resource records:

    A
    AAAA
    NS
    CNAME
    MX
    TXT
    SOA
"""

from __future__ import annotations

from idns.model import (
    DNSMessage,
    DNSName,
    DNSQuestion,
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)

from idns.wire.cursor import ByteCursor, DNSBoundsError
from idns.wire.header_codec import DNSHeaderCodec
from idns.wire.question_codec import DNSQuestionCodec
from idns.wire.compression import DNSCompressionDecoder
from idns.wire.rdata_codec import (
    DNSAddressRDataCodec,
    DNSNSRDataCodec,
    DNSCNameRDataCodec,
    DNSMXRDataCodec,
    DNSTXTRDataCodec,
    DNSSOARDataCodec,
)


# ============================================================
# ERRORS
# ============================================================


class DNSMessageDecoderError(Exception):
    """Base exception for DNS message decoding errors."""


class DNSMessageDecodeError(DNSMessageDecoderError):
    """Raised when a DNS message cannot be decoded."""


class DNSUnsupportedRecordTypeError(DNSMessageDecodeError):
    """Raised when an unsupported DNS record type is encountered."""


# ============================================================
# DNS TYPE MAP
# ============================================================


TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28


TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
}


# ============================================================
# DNS CLASS MAP
# ============================================================


CLASS_IN = 1


# ============================================================
# MESSAGE DECODER
# ============================================================


class DNSMessageDecoder:
    """
    Decoder for complete DNS wire-format messages.
    """

    # --------------------------------------------------------
    # PUBLIC ENTRY POINT
    # --------------------------------------------------------

    @classmethod
    def decode(cls, data: bytes) -> DNSMessage:
        """
        Decode a complete DNS packet.

        Args:
            data:
                Raw DNS wire-format packet.

        Returns:
            DNSMessage

        Raises:
            DNSMessageDecodeError:
                If the packet is malformed.
        """

        if not isinstance(data, bytes):
            raise DNSMessageDecodeError(
                "DNS message must be bytes"
            )

        cursor = ByteCursor(data)

        try:
            # ------------------------------------------------
            # 1. HEADER
            # ------------------------------------------------

            header = DNSHeaderCodec.decode(cursor)

            # ------------------------------------------------
            # 2. QUESTIONS
            # ------------------------------------------------

            questions = []

            for _ in range(header.qdcount):
                question = DNSQuestionCodec.decode(cursor)
                questions.append(question)

            # ------------------------------------------------
            # 3. ANSWERS
            # ------------------------------------------------

            answers = []

            for _ in range(header.ancount):
                record = cls._decode_record(cursor, data)
                answers.append(record)

            # ------------------------------------------------
            # 4. AUTHORITY
            # ------------------------------------------------

            authorities = []

            for _ in range(header.nscount):
                record = cls._decode_record(cursor, data)
                authorities.append(record)

            # ------------------------------------------------
            # 5. ADDITIONAL
            # ------------------------------------------------

            additionals = []

            for _ in range(header.arcount):
                record = cls._decode_record(cursor, data)
                additionals.append(record)

            # ------------------------------------------------
            # 6. RETURN DNS MESSAGE
            # ------------------------------------------------

            return DNSMessage(
                header=header,
                questions=questions,
                answers=answers,
                authorities=authorities,
                additionals=additionals,
            )

        except DNSMessageDecoderError:
            raise

        except Exception as exc:
            raise DNSMessageDecodeError(
                "failed to decode DNS message"
            ) from exc

    # ========================================================
    # RESOURCE RECORD DECODER
    # ========================================================

    @classmethod
    def _decode_record(
        cls,
        cursor: ByteCursor,
        packet: bytes,
    ):
        """
        Decode one DNS Resource Record.

        Wire format:

            NAME
            TYPE
            CLASS
            TTL
            RDLENGTH
            RDATA
        """

        # ----------------------------------------------------
        # NAME
        # ----------------------------------------------------

        try:
            name = DNSCompressionDecoder.decode(cursor)
        except Exception as exc:
            raise DNSMessageDecodeError(
                "failed to decode resource record name"
            ) from exc

        # ----------------------------------------------------
        # TYPE
        # ----------------------------------------------------

        try:
            record_type = cursor.read_u16()
        except DNSBoundsError as exc:
            raise DNSMessageDecodeError(
                "truncated resource record type"
            ) from exc

        # ----------------------------------------------------
        # CLASS
        # ----------------------------------------------------

        try:
            record_class = cursor.read_u16()
        except DNSBoundsError as exc:
            raise DNSMessageDecodeError(
                "truncated resource record class"
            ) from exc

        if record_class != CLASS_IN:
            raise DNSMessageDecodeError(
                f"unsupported DNS class: {record_class}"
            )

        # ----------------------------------------------------
        # TTL
        # ----------------------------------------------------

        try:
            ttl = cursor.read_u32()
        except DNSBoundsError as exc:
            raise DNSMessageDecodeError(
                "truncated resource record TTL"
            ) from exc

        # ----------------------------------------------------
        # RDLENGTH
        # ----------------------------------------------------

        try:
            rdlength = cursor.read_u16()
        except DNSBoundsError as exc:
            raise DNSMessageDecodeError(
                "truncated resource record RDLENGTH"
            ) from exc

        # ----------------------------------------------------
        # RDATA START
        # ----------------------------------------------------

        rdata_start = cursor.position

        if cursor.remaining() < rdlength:
            raise DNSMessageDecodeError(
                "RDATA extends beyond DNS packet"
            )

        # ----------------------------------------------------
        # RDATA DISPATCH
        # ----------------------------------------------------

        try:
            if record_type == TYPE_A:

                address = DNSAddressRDataCodec.decode_a(cursor)

                cls._verify_rdata_length(
                    cursor,
                    rdata_start,
                    rdlength,
                    expected=4,
                )

                return ARecord(
                    name=name,
                    address=address,
                    ttl=ttl,
                )

            # ------------------------------------------------
            # AAAA
            # ------------------------------------------------

            if record_type == TYPE_AAAA:

                address = DNSAddressRDataCodec.decode_aaaa(cursor)

                cls._verify_rdata_length(
                    cursor,
                    rdata_start,
                    rdlength,
                    expected=16,
                )

                return AAAARecord(
                    name=name,
                    address=address,
                    ttl=ttl,
                )

            # ------------------------------------------------
            # NS
            # ------------------------------------------------

            if record_type == TYPE_NS:

                nameserver = DNSNSRDataCodec.decode(cursor)

                cls._verify_rdata_consumed(
                    cursor,
                    rdata_start,
                    rdlength,
                )

                return NSRecord(
                    name=name,
                    nameserver=nameserver,
                    ttl=ttl,
                )

            # ------------------------------------------------
            # CNAME
            # ------------------------------------------------

            if record_type == TYPE_CNAME:

                canonical_name = DNSCNameRDataCodec.decode(
                    cursor
                )

                cls._verify_rdata_consumed(
                    cursor,
                    rdata_start,
                    rdlength,
                )

                return CNAMERecord(
                    name=name,
                    canonical_name=canonical_name,
                    ttl=ttl,
                )

            # ------------------------------------------------
            # MX
            # ------------------------------------------------

            if record_type == TYPE_MX:

                preference, exchange = (
                    DNSMXRDataCodec.decode(cursor)
                )

                cls._verify_rdata_consumed(
                    cursor,
                    rdata_start,
                    rdlength,
                )

                return MXRecord(
                    name=name,
                    preference=preference,
                    exchange=exchange,
                    ttl=ttl,
                )

            # ------------------------------------------------
            # TXT
            # ------------------------------------------------

            if record_type == TYPE_TXT:

                text = DNSTXTRDataCodec.decode(
                    cursor,
                    length=rdlength,
                )

                cls._verify_rdata_consumed(
                    cursor,
                    rdata_start,
                    rdlength,
                )

                return TXTRecord(
                    name=name,
                    text=tuple(text),
                    ttl=ttl,
                )

            # ------------------------------------------------
            # SOA
            # ------------------------------------------------

            if record_type == TYPE_SOA:

                (
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                ) = DNSSOARDataCodec.decode(cursor)

                cls._verify_rdata_consumed(
                    cursor,
                    rdata_start,
                    rdlength,
                )

                return SOARecord(
                    name=name,
                    mname=mname,
                    rname=rname,
                    serial=serial,
                    refresh=refresh,
                    retry=retry,
                    expire=expire,
                    minimum=minimum,
                    ttl=ttl,
                )

        except DNSBoundsError as exc:
            raise DNSMessageDecodeError(
                "truncated resource record RDATA"
            ) from exc

        except DNSMessageDecoderError:
            raise

        except Exception as exc:
            raise DNSMessageDecodeError(
                f"failed to decode RDATA for type "
                f"{record_type}"
            ) from exc

        # ----------------------------------------------------
        # UNSUPPORTED TYPE
        # ----------------------------------------------------

        raise DNSUnsupportedRecordTypeError(
            f"unsupported DNS record type: "
            f"{record_type}"
        )

    # ========================================================
    # RDATA VALIDATION
    # ========================================================

    @staticmethod
    def _verify_rdata_length(
        cursor: ByteCursor,
        rdata_start: int,
        rdlength: int,
        expected: int,
    ) -> None:
        """
        Verify fixed-size RDATA length.
        """

        consumed = cursor.position - rdata_start

        if rdlength != expected:
            raise DNSMessageDecodeError(
                f"invalid RDLENGTH: expected "
                f"{expected}, got {rdlength}"
            )

        if consumed != rdlength:
            raise DNSMessageDecodeError(
                f"RDATA length mismatch: consumed "
                f"{consumed}, expected {rdlength}"
            )

    @staticmethod
    def _verify_rdata_consumed(
        cursor: ByteCursor,
        rdata_start: int,
        rdlength: int,
    ) -> None:
        """
        Verify that the RDATA decoder consumed
        exactly RDLENGTH bytes.
        """

        consumed = cursor.position - rdata_start

        if consumed != rdlength:
            raise DNSMessageDecodeError(
                f"RDATA length mismatch: consumed "
                f"{consumed}, expected {rdlength}"
            )