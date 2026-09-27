"""
DNS RDATA codecs.

Owner: Avidipta
Phase: Phase 3
Tasks: 3.3, 3.4, 3.5

Implements RDATA encoding and decoding for:

- A
- AAAA
- NS
- CNAME
- MX
- TXT
- SOA
"""

from __future__ import annotations

import ipaddress
import struct

from idns.model import DNSName

from idns.wire.cursor import (
    ByteCursor,
    DNSBoundsError,
)

from idns.wire.compression import (
    DNSCompressionDecoder,
    DNSCompressionEncodeError,
    DNSCompressionEncoder,
)


# ============================================================
# BASE ERRORS
# ============================================================


class DNSRDataCodecError(Exception):
    """Base exception for DNS RDATA codec errors."""


class DNSRDataEncodeError(DNSRDataCodecError):
    """Raised when RDATA cannot be encoded."""


class DNSRDataDecodeError(DNSRDataCodecError):
    """Raised when RDATA cannot be decoded."""


# ============================================================
# 3.3 - A / AAAA RDATA
# ============================================================


class DNSAddressRDataCodec:
    """Codec for A and AAAA DNS RDATA."""

    A_LENGTH = 4
    AAAA_LENGTH = 16

    @classmethod
    def encode_a(cls, address: str) -> bytes:
        """Encode an IPv4 address."""

        try:
            ip = ipaddress.IPv4Address(address)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise DNSRDataEncodeError(
                f"invalid IPv4 address: {address!r}"
            ) from exc

        packed = ip.packed

        if len(packed) != cls.A_LENGTH:
            raise DNSRDataEncodeError(
                "IPv4 address must encode to exactly 4 bytes"
            )

        return packed

    @classmethod
    def decode_a(cls, cursor: ByteCursor) -> str:
        """Decode 4 bytes of IPv4 RDATA."""

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        try:
            data = cursor.read_bytes(cls.A_LENGTH)
        except DNSBoundsError as exc:
            raise DNSRDataDecodeError(
                "insufficient bytes for IPv4 RDATA"
            ) from exc

        try:
            return str(ipaddress.IPv4Address(data))
        except ipaddress.AddressValueError as exc:
            raise DNSRDataDecodeError(
                "invalid IPv4 RDATA"
            ) from exc

    @classmethod
    def encode_aaaa(cls, address: str) -> bytes:
        """Encode an IPv6 address."""

        try:
            ip = ipaddress.IPv6Address(address)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise DNSRDataEncodeError(
                f"invalid IPv6 address: {address!r}"
            ) from exc

        packed = ip.packed

        if len(packed) != cls.AAAA_LENGTH:
            raise DNSRDataEncodeError(
                "IPv6 address must encode to exactly 16 bytes"
            )

        return packed

    @classmethod
    def decode_aaaa(cls, cursor: ByteCursor) -> str:
        """Decode 16 bytes of IPv6 RDATA."""

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        try:
            data = cursor.read_bytes(cls.AAAA_LENGTH)
        except DNSBoundsError as exc:
            raise DNSRDataDecodeError(
                "insufficient bytes for IPv6 RDATA"
            ) from exc

        try:
            return str(ipaddress.IPv6Address(data))
        except ipaddress.AddressValueError as exc:
            raise DNSRDataDecodeError(
                "invalid IPv6 RDATA"
            ) from exc


class DNSAddressRData:
    """Generic dispatcher for A and AAAA RDATA."""

    @classmethod
    def encode(
        cls,
        record_type: str,
        address: str,
    ) -> bytes:

        record_type = record_type.upper()

        if record_type == "A":
            return DNSAddressRDataCodec.encode_a(address)

        if record_type == "AAAA":
            return DNSAddressRDataCodec.encode_aaaa(address)

        raise DNSRDataEncodeError(
            f"unsupported address record type: {record_type!r}"
        )

    @classmethod
    def decode(
        cls,
        record_type: str,
        cursor: ByteCursor,
    ) -> str:

        record_type = record_type.upper()

        if record_type == "A":
            return DNSAddressRDataCodec.decode_a(cursor)

        if record_type == "AAAA":
            return DNSAddressRDataCodec.decode_aaaa(cursor)

        raise DNSRDataDecodeError(
            f"unsupported address record type: {record_type!r}"
        )


# ============================================================
# 3.4 - NS / CNAME RDATA
# ============================================================


class DNSNameRDataCodec:
    """Codec for DNS RDATA fields containing domain names."""

    @classmethod
    def encode_name(
        cls,
        name: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        if not isinstance(encoder, DNSCompressionEncoder):
            raise DNSRDataEncodeError(
                "encoder must be a DNSCompressionEncoder"
            )

        try:
            return encoder.encode(
                name,
                current_offset=current_offset,
            )
        except DNSCompressionEncodeError as exc:
            raise DNSRDataEncodeError(
                f"failed to encode DNS name RDATA: {name!r}"
            ) from exc

    @classmethod
    def decode_name(
        cls,
        cursor: ByteCursor,
    ) -> DNSName:

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        try:
            return DNSCompressionDecoder.decode(cursor)
        except Exception as exc:
            raise DNSRDataDecodeError(
                "failed to decode DNS name RDATA"
            ) from exc


class DNSNSRDataCodec:
    """Codec for NS record RDATA."""

    @classmethod
    def encode(
        cls,
        nameserver: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        return DNSNameRDataCodec.encode_name(
            nameserver,
            encoder,
            current_offset,
        )

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> DNSName:

        return DNSNameRDataCodec.decode_name(cursor)


class DNSCNameRDataCodec:
    """Codec for CNAME record RDATA."""

    @classmethod
    def encode(
        cls,
        canonical_name: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        return DNSNameRDataCodec.encode_name(
            canonical_name,
            encoder,
            current_offset,
        )

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> DNSName:

        return DNSNameRDataCodec.decode_name(cursor)


class DNSNameRData:
    """Generic dispatcher for NS and CNAME RDATA."""

    @classmethod
    def encode(
        cls,
        record_type: str,
        name: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        record_type = record_type.upper()

        if record_type == "NS":
            return DNSNSRDataCodec.encode(
                name,
                encoder,
                current_offset,
            )

        if record_type == "CNAME":
            return DNSCNameRDataCodec.encode(
                name,
                encoder,
                current_offset,
            )

        raise DNSRDataEncodeError(
            f"unsupported name record type: {record_type!r}"
        )

    @classmethod
    def decode(
        cls,
        record_type: str,
        cursor: ByteCursor,
    ) -> DNSName:

        record_type = record_type.upper()

        if record_type == "NS":
            return DNSNSRDataCodec.decode(cursor)

        if record_type == "CNAME":
            return DNSCNameRDataCodec.decode(cursor)

        raise DNSRDataDecodeError(
            f"unsupported name record type: {record_type!r}"
        )


# ============================================================
# 3.5 - MX RDATA
# ============================================================


class DNSMXRDataCodec:
    """
    Codec for MX record RDATA.

    MX RDATA:

        +----------------+
        |   PREFERENCE   |  2 bytes
        +----------------+
        |    EXCHANGE    |  DNS name
        +----------------+
    """

    @classmethod
    def encode(
        cls,
        preference: int,
        exchange: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:
        """Encode MX RDATA."""

        if not isinstance(preference, int):
            raise DNSRDataEncodeError(
                "MX preference must be an integer"
            )

        if not 0 <= preference <= 65535:
            raise DNSRDataEncodeError(
                "MX preference must be between 0 and 65535"
            )

        try:
            encoded_preference = struct.pack(
                "!H",
                preference,
            )
        except struct.error as exc:
            raise DNSRDataEncodeError(
                "invalid MX preference"
            ) from exc

        exchange_offset = current_offset + 2

        exchange_bytes = DNSNameRDataCodec.encode_name(
            exchange,
            encoder,
            exchange_offset,
        )

        return encoded_preference + exchange_bytes

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> tuple[int, DNSName]:
        """Decode MX RDATA."""

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        try:
            preference = cursor.read_u16()
        except DNSBoundsError as exc:
            raise DNSRDataDecodeError(
                "insufficient bytes for MX preference"
            ) from exc

        exchange = DNSNameRDataCodec.decode_name(cursor)

        return preference, exchange


# ============================================================
# 3.5 - TXT RDATA
# ============================================================


class DNSTXTRDataCodec:
    """
    Codec for TXT record RDATA.

    TXT consists of one or more character strings.

    Each string is encoded as:

        +--------+-------------------+
        | LENGTH |       DATA        |
        +--------+-------------------+

    LENGTH is one byte.
    """

    MAX_STRING_LENGTH = 255

    @classmethod
    def encode(
        cls,
        text: tuple[str, ...] | list[str] | str,
    ) -> bytes:
        """Encode TXT RDATA."""

        if isinstance(text, str):
            strings = (text,)
        elif isinstance(text, (tuple, list)):
            strings = tuple(text)
        else:
            raise DNSRDataEncodeError(
                "TXT data must be a string, tuple, or list"
            )

        encoded = bytearray()

        for value in strings:
            if not isinstance(value, str):
                raise DNSRDataEncodeError(
                    "TXT strings must contain only strings"
                )

            try:
                data = value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise DNSRDataEncodeError(
                    f"TXT string cannot be UTF-8 encoded: {value!r}"
                ) from exc

            if len(data) > cls.MAX_STRING_LENGTH:
                raise DNSRDataEncodeError(
                    "TXT string exceeds 255 bytes"
                )

            encoded.append(len(data))
            encoded.extend(data)

        return bytes(encoded)

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
        length: int | None = None,
    ) -> tuple[str, ...]:
        """Decode TXT RDATA."""

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        if length is None:
            remaining = cursor.remaining()
        else:
            if length < 0:
                raise DNSRDataDecodeError(
                    "TXT RDATA length cannot be negative"
                )

            if length > cursor.remaining():
                raise DNSRDataDecodeError(
                    "TXT RDATA length exceeds remaining packet data"
                )

            remaining = length

        strings: list[str] = []
        consumed = 0

        while consumed < remaining:
            try:
                string_length = cursor.read_u8()
            except DNSBoundsError as exc:
                raise DNSRDataDecodeError(
                    "unexpected end of TXT RDATA"
                ) from exc

            consumed += 1

            if consumed + string_length > remaining:
                raise DNSRDataDecodeError(
                    "TXT string exceeds RDATA boundary"
                )

            try:
                data = cursor.read_bytes(string_length)
            except DNSBoundsError as exc:
                raise DNSRDataDecodeError(
                    "unexpected end of TXT string"
                ) from exc

            consumed += string_length

            try:
                strings.append(
                    data.decode("utf-8")
                )
            except UnicodeDecodeError as exc:
                raise DNSRDataDecodeError(
                    "TXT data is not valid UTF-8"
                ) from exc

        return tuple(strings)


# ============================================================
# 3.5 - SOA RDATA
# ============================================================


class DNSSOARDataCodec:
    """
    Codec for SOA record RDATA.

    SOA RDATA:

        MNAME
        RNAME
        SERIAL
        REFRESH
        RETRY
        EXPIRE
        MINIMUM
    """

    @classmethod
    def encode(
        cls,
        mname: DNSName | str,
        rname: DNSName | str,
        serial: int,
        refresh: int,
        retry: int,
        expire: int,
        minimum: int,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:
        """Encode SOA RDATA."""

        values = {
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }

        for field_name, value in values.items():
            if not isinstance(value, int):
                raise DNSRDataEncodeError(
                    f"SOA {field_name} must be an integer"
                )

            if not 0 <= value <= 0xFFFFFFFF:
                raise DNSRDataEncodeError(
                    f"SOA {field_name} must be between 0 and 4294967295"
                )

        # MNAME starts at current_offset.
        mname_bytes = DNSNameRDataCodec.encode_name(
            mname,
            encoder,
            current_offset,
        )

        # RNAME starts immediately after MNAME.
        rname_offset = (
            current_offset
            + len(mname_bytes)
        )

        rname_bytes = DNSNameRDataCodec.encode_name(
            rname,
            encoder,
            rname_offset,
        )

        fixed_fields = struct.pack(
            "!IIIII",
            serial,
            refresh,
            retry,
            expire,
            minimum,
        )

        return (
            mname_bytes
            + rname_bytes
            + fixed_fields
        )

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> tuple[
        DNSName,
        DNSName,
        int,
        int,
        int,
        int,
        int,
    ]:
        """Decode SOA RDATA."""

        if not isinstance(cursor, ByteCursor):
            raise DNSRDataDecodeError(
                "cursor must be a ByteCursor"
            )

        mname = DNSNameRDataCodec.decode_name(cursor)

        rname = DNSNameRDataCodec.decode_name(cursor)

        try:
            serial = cursor.read_u32()
            refresh = cursor.read_u32()
            retry = cursor.read_u32()
            expire = cursor.read_u32()
            minimum = cursor.read_u32()
        except DNSBoundsError as exc:
            raise DNSRDataDecodeError(
                "insufficient bytes for SOA numeric fields"
            ) from exc

        return (
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        )


# ============================================================
# 3.5 - GENERIC MX / TXT / SOA DISPATCH
# ============================================================


class DNSAdvancedRData:
    """
    Generic dispatcher for MX, TXT, and SOA RDATA.
    """

    @classmethod
    def encode_mx(
        cls,
        preference: int,
        exchange: DNSName | str,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        return DNSMXRDataCodec.encode(
            preference,
            exchange,
            encoder,
            current_offset,
        )

    @classmethod
    def decode_mx(
        cls,
        cursor: ByteCursor,
    ) -> tuple[int, DNSName]:

        return DNSMXRDataCodec.decode(cursor)

    @classmethod
    def encode_txt(
        cls,
        text: tuple[str, ...] | list[str] | str,
    ) -> bytes:

        return DNSTXTRDataCodec.encode(text)

    @classmethod
    def decode_txt(
        cls,
        cursor: ByteCursor,
        length: int | None = None,
    ) -> tuple[str, ...]:

        return DNSTXTRDataCodec.decode(
            cursor,
            length,
        )

    @classmethod
    def encode_soa(
        cls,
        mname: DNSName | str,
        rname: DNSName | str,
        serial: int,
        refresh: int,
        retry: int,
        expire: int,
        minimum: int,
        encoder: DNSCompressionEncoder,
        current_offset: int,
    ) -> bytes:

        return DNSSOARDataCodec.encode(
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            encoder,
            current_offset,
        )

    @classmethod
    def decode_soa(
        cls,
        cursor: ByteCursor,
    ) -> tuple[
        DNSName,
        DNSName,
        int,
        int,
        int,
        int,
        int,
    ]:

        return DNSSOARDataCodec.decode(cursor)