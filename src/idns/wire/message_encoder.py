"""
DNS Message Encoder.

Phase: Phase 3
Task: 3.7

Encodes a complete DNS message into DNS wire format.

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

import struct

from idns.model import (
    DNSMessage,
    DNSQuestion,
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)

from idns.wire.header_codec import DNSHeaderCodec
from idns.wire.question_codec import DNSQuestionCodec
from idns.wire.compression import DNSCompressionEncoder
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


class DNSMessageEncoderError(Exception):
    """Base exception for DNS message encoding errors."""


class DNSMessageEncodeError(DNSMessageEncoderError):
    """Raised when a DNS message cannot be encoded."""


class DNSUnsupportedRecordTypeError(DNSMessageEncodeError):
    """Raised when an unsupported record type is encountered."""


# ============================================================
# DNS TYPE CODES
# ============================================================


TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28


# ============================================================
# DNS CLASS
# ============================================================


CLASS_IN = 1


# ============================================================
# MESSAGE ENCODER
# ============================================================


class DNSMessageEncoder:
    """
    Encoder for complete DNS wire-format messages.
    """

    # --------------------------------------------------------
    # PUBLIC ENTRY POINT
    # --------------------------------------------------------

    @classmethod
    def encode(cls, message: DNSMessage) -> bytes:
        """
        Encode a complete DNSMessage into wire format.

        Args:
            message:
                DNSMessage instance.

        Returns:
            Raw DNS packet bytes.
        """

        if not isinstance(message, DNSMessage):
            raise DNSMessageEncodeError(
                "message must be a DNSMessage"
            )

        try:
            # Shared compression state for the entire packet.
            encoder = DNSCompressionEncoder()

            packet = bytearray()

            # ------------------------------------------------
            # 1. HEADER
            # ------------------------------------------------

            header = DNSHeaderCodec.encode(message.header)

            packet.extend(header)

            # ------------------------------------------------
            # 2. QUESTIONS
            # ------------------------------------------------

            for question in message.questions:
                encoded_question = cls._encode_question(
                    question,
                    encoder,
                    len(packet),
                )

                packet.extend(encoded_question)

            # ------------------------------------------------
            # 3. ANSWERS
            # ------------------------------------------------

            for record in message.answers:
                encoded_record = cls._encode_record(
                    record,
                    encoder,
                    len(packet),
                )

                packet.extend(encoded_record)

            # ------------------------------------------------
            # 4. AUTHORITY
            # ------------------------------------------------

            for record in message.authorities:
                encoded_record = cls._encode_record(
                    record,
                    encoder,
                    len(packet),
                )

                packet.extend(encoded_record)

            # ------------------------------------------------
            # 5. ADDITIONAL
            # ------------------------------------------------

            for record in message.additionals:
                encoded_record = cls._encode_record(
                    record,
                    encoder,
                    len(packet),
                )

                packet.extend(encoded_record)

            return bytes(packet)

        except DNSMessageEncoderError:
            raise

        except Exception as exc:
            raise DNSMessageEncodeError(
                "failed to encode DNS message"
            ) from exc

    # ========================================================
    # QUESTION ENCODER
    # ========================================================

    @classmethod
    def _encode_question(
        cls,
        question: DNSQuestion,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:
        """
        Encode one DNS question.

        Question format:

            QNAME
            QTYPE
            QCLASS
        """

        try:
            # ------------------------------------------------
            # QNAME
            # ------------------------------------------------

            qname = encoder.encode(
                question.qname,
                current_offset=current_offset,
            )

            # ------------------------------------------------
            # QTYPE / QCLASS
            # ------------------------------------------------

            fixed = struct.pack(
                "!HH",
                question.qtype_code,
                question.qclass_code,
            )

            return qname + fixed

        except Exception as exc:
            raise DNSMessageEncodeError(
                "failed to encode DNS question"
            ) from exc

    # ========================================================
    # RESOURCE RECORD ENCODER
    # ========================================================

    @classmethod
    def _encode_record(
        cls,
        record,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:
        """
        Encode one DNS Resource Record.

        Wire format:

            NAME
            TYPE
            CLASS
            TTL
            RDLENGTH
            RDATA
        """

        # ----------------------------------------------------
        # A
        # ----------------------------------------------------

        if isinstance(record, ARecord):
            return cls._encode_a_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # AAAA
        # ----------------------------------------------------

        if isinstance(record, AAAARecord):
            return cls._encode_aaaa_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # NS
        # ----------------------------------------------------

        if isinstance(record, NSRecord):
            return cls._encode_ns_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # CNAME
        # ----------------------------------------------------

        if isinstance(record, CNAMERecord):
            return cls._encode_cname_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # MX
        # ----------------------------------------------------

        if isinstance(record, MXRecord):
            return cls._encode_mx_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # TXT
        # ----------------------------------------------------

        if isinstance(record, TXTRecord):
            return cls._encode_txt_record(
                record,
                encoder,
                current_offset,
            )

        # ----------------------------------------------------
        # SOA
        # ----------------------------------------------------

        if isinstance(record, SOARecord):
            return cls._encode_soa_record(
                record,
                encoder,
                current_offset,
            )

        raise DNSUnsupportedRecordTypeError(
            f"unsupported record type: "
            f"{type(record).__name__}"
        )

    # ========================================================
    # A
    # ========================================================

    @classmethod
    def _encode_a_record(
        cls,
        record: ARecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata = DNSAddressRDataCodec.encode_a(
            record.address
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_A,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # AAAA
    # ========================================================

    @classmethod
    def _encode_aaaa_record(
        cls,
        record: AAAARecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata = DNSAddressRDataCodec.encode_aaaa(
            record.address
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_AAAA,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # NS
    # ========================================================

    @classmethod
    def _encode_ns_record(
        cls,
        record: NSRecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata_offset = (
            current_offset
            + len(name)
            + 2
            + 2
            + 4
            + 2
        )

        rdata = DNSNSRDataCodec.encode(
            record.nameserver,
            encoder,
            current_offset=rdata_offset,
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_NS,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # CNAME
    # ========================================================

    @classmethod
    def _encode_cname_record(
        cls,
        record: CNAMERecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata_offset = (
            current_offset
            + len(name)
            + 2
            + 2
            + 4
            + 2
        )

        rdata = DNSCNameRDataCodec.encode(
            record.canonical_name,
            encoder,
            current_offset=rdata_offset,
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_CNAME,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # MX
    # ========================================================

    @classmethod
    def _encode_mx_record(
        cls,
        record: MXRecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata_offset = (
            current_offset
            + len(name)
            + 2
            + 2
            + 4
            + 2
        )

        rdata = DNSMXRDataCodec.encode(
            record.preference,
            record.exchange,
            encoder,
            current_offset=rdata_offset,
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_MX,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # TXT
    # ========================================================

    @classmethod
    def _encode_txt_record(
        cls,
        record: TXTRecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata = DNSTXTRDataCodec.encode(
            record.text
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_TXT,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # SOA
    # ========================================================

    @classmethod
    def _encode_soa_record(
        cls,
        record: SOARecord,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        name = encoder.encode(
            record.name,
            current_offset=current_offset,
        )

        rdata_offset = (
            current_offset
            + len(name)
            + 2
            + 2
            + 4
            + 2
        )

        rdata = DNSSOARDataCodec.encode(
            record.mname,
            record.rname,
            record.serial,
            record.refresh,
            record.retry,
            record.expire,
            record.minimum,
            encoder,
            current_offset=rdata_offset,
        )

        return cls._build_record(
            name=name,
            record_type=TYPE_SOA,
            ttl=record.ttl,
            rdata=rdata,
        )

    # ========================================================
    # BUILD RESOURCE RECORD
    # ========================================================

    @staticmethod
    def _build_record(
        name: bytes,
        record_type: int,
        ttl: int,
        rdata: bytes,
    ) -> bytes:
        """
        Build:

            NAME
            TYPE
            CLASS
            TTL
            RDLENGTH
            RDATA
        """

        if not isinstance(ttl, int):
            raise DNSMessageEncodeError(
                "TTL must be an integer"
            )

        if ttl < 0 or ttl > 0xFFFFFFFF:
            raise DNSMessageEncodeError(
                f"TTL out of range: {ttl}"
            )

        if len(rdata) > 0xFFFF:
            raise DNSMessageEncodeError(
                "RDATA exceeds maximum DNS RDLENGTH"
            )

        fixed = struct.pack(
            "!HHIH",
            record_type,
            CLASS_IN,
            ttl,
            len(rdata),
        )

        return name + fixed + rdata