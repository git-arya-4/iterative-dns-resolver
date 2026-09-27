"""
Tests for DNS RDATA codecs.

Phase 3:
    3.3 - A / AAAA / NS / CNAME
    3.5 - MX / TXT / SOA
"""

import struct

import pytest

from idns.model import DNSName
from idns.wire.cursor import ByteCursor
from idns.wire.rdata_codec import (
    DNSRDataDecodeError,
    DNSRDataEncodeError,
    DNSAddressRData,
    DNSAddressRDataCodec,
    DNSNameRData,
    DNSNSRDataCodec,
    DNSCNameRDataCodec,
    DNSMXRDataCodec,
    DNSTXTRDataCodec,
    DNSSOARDataCodec,
)
from idns.wire.compression import DNSCompressionEncoder


# ============================================================
# A RDATA
# ============================================================


def test_encode_a():
    encoded = DNSAddressRDataCodec.encode_a("192.168.1.1")

    assert encoded == b"\xc0\xa8\x01\x01"
    assert len(encoded) == 4


def test_decode_a():
    cursor = ByteCursor(b"\xc0\xa8\x01\x01")

    decoded = DNSAddressRDataCodec.decode_a(cursor)

    assert decoded == "192.168.1.1"
    assert cursor.at_end()


def test_encode_a_loopback():
    encoded = DNSAddressRDataCodec.encode_a("127.0.0.1")

    assert encoded == b"\x7f\x00\x00\x01"


def test_decode_a_loopback():
    cursor = ByteCursor(b"\x7f\x00\x00\x01")

    decoded = DNSAddressRDataCodec.decode_a(cursor)

    assert decoded == "127.0.0.1"


def test_invalid_ipv4():
    with pytest.raises(DNSRDataEncodeError):
        DNSAddressRDataCodec.encode_a("999.999.999.999")


def test_invalid_ipv4_text():
    with pytest.raises(DNSRDataEncodeError):
        DNSAddressRDataCodec.encode_a("not-an-ip")


def test_truncated_a():
    cursor = ByteCursor(b"\xc0\xa8\x01")

    with pytest.raises(DNSRDataDecodeError):
        DNSAddressRDataCodec.decode_a(cursor)


# ============================================================
# AAAA RDATA
# ============================================================


def test_encode_aaaa():
    encoded = DNSAddressRDataCodec.encode_aaaa("2001:db8::1")

    assert len(encoded) == 16
    assert encoded == bytes.fromhex(
        "20010db8000000000000000000000001"
    )


def test_decode_aaaa():
    cursor = ByteCursor(
        bytes.fromhex("20010db8000000000000000000000001")
    )

    decoded = DNSAddressRDataCodec.decode_aaaa(cursor)

    assert decoded == "2001:db8::1"
    assert cursor.at_end()


def test_encode_aaaa_loopback():
    encoded = DNSAddressRDataCodec.encode_aaaa("::1")

    assert encoded == b"\x00" * 15 + b"\x01"


def test_decode_aaaa_loopback():
    cursor = ByteCursor(b"\x00" * 15 + b"\x01")

    decoded = DNSAddressRDataCodec.decode_aaaa(cursor)

    assert decoded == "::1"


def test_invalid_ipv6():
    with pytest.raises(DNSRDataEncodeError):
        DNSAddressRDataCodec.encode_aaaa(
            "2001:db8:zzzz::1"
        )


def test_invalid_ipv6_text():
    with pytest.raises(DNSRDataEncodeError):
        DNSAddressRDataCodec.encode_aaaa("not-an-ipv6")


def test_truncated_aaaa():
    cursor = ByteCursor(b"\x00" * 15)

    with pytest.raises(DNSRDataDecodeError):
        DNSAddressRDataCodec.decode_aaaa(cursor)


# ============================================================
# GENERIC A / AAAA DISPATCH
# ============================================================


def test_generic_encode_a():
    encoded = DNSAddressRData.encode(
        "A",
        "8.8.8.8",
    )

    assert encoded == b"\x08\x08\x08\x08"


def test_generic_encode_aaaa():
    encoded = DNSAddressRData.encode(
        "AAAA",
        "2001:4860:4860::8888",
    )

    assert len(encoded) == 16


def test_generic_decode_a():
    cursor = ByteCursor(b"\x08\x08\x08\x08")

    decoded = DNSAddressRData.decode(
        "A",
        cursor,
    )

    assert decoded == "8.8.8.8"


def test_generic_decode_aaaa():
    cursor = ByteCursor(
        bytes.fromhex(
            "20014860486000000000000000008888"
        )
    )

    decoded = DNSAddressRData.decode(
        "AAAA",
        cursor,
    )

    assert decoded == "2001:4860:4860::8888"


def test_unsupported_encode_type():
    with pytest.raises(DNSRDataEncodeError):
        DNSAddressRData.encode(
            "MX",
            "8.8.8.8",
        )


def test_unsupported_decode_type():
    cursor = ByteCursor(b"\x00" * 4)

    with pytest.raises(DNSRDataDecodeError):
        DNSAddressRData.decode(
            "MX",
            cursor,
        )


# ============================================================
# NS RDATA
# ============================================================


def test_encode_ns():
    encoder = DNSCompressionEncoder()

    encoded = DNSNSRDataCodec.encode(
        "ns1.example.com",
        encoder,
        current_offset=0,
    )

    expected = (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    assert encoded == expected


def test_decode_ns():
    packet = (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    decoded = DNSNSRDataCodec.decode(cursor)

    assert str(decoded) == "ns1.example.com"


def test_ns_compression():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    second = DNSNSRDataCodec.encode(
        "ns1.example.com",
        encoder,
        current_offset=len(first),
    )

    expected = (
        b"\x03ns1"
        b"\xc0\x00"
    )

    assert second == expected


# ============================================================
# CNAME RDATA
# ============================================================


def test_encode_cname():
    encoder = DNSCompressionEncoder()

    encoded = DNSCNameRDataCodec.encode(
        "www.example.com",
        encoder,
        current_offset=0,
    )

    expected = (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    assert encoded == expected


def test_decode_cname():
    packet = (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    decoded = DNSCNameRDataCodec.decode(cursor)

    assert str(decoded) == "www.example.com"


def test_cname_compression():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    second = DNSCNameRDataCodec.encode(
        "www.example.com",
        encoder,
        current_offset=len(first),
    )

    expected = (
        b"\x03www"
        b"\xc0\x00"
    )

    assert second == expected


# ============================================================
# GENERIC NS / CNAME DISPATCH
# ============================================================


def test_generic_ns_dispatch():
    encoder = DNSCompressionEncoder()

    encoded = DNSNameRData.encode(
        "NS",
        "ns1.example.com",
        encoder,
        current_offset=0,
    )

    assert encoded == (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_generic_cname_dispatch():
    encoder = DNSCompressionEncoder()

    encoded = DNSNameRData.encode(
        "CNAME",
        "www.example.com",
        encoder,
        current_offset=0,
    )

    assert encoded == (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_unsupported_name_rdata_type():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSRDataEncodeError):
        DNSNameRData.encode(
            "MX",
            "mail.example.com",
            encoder,
            current_offset=0,
        )


# ============================================================
# MX RDATA
# ============================================================


def test_encode_mx():
    encoder = DNSCompressionEncoder()

    encoded = DNSMXRDataCodec.encode(
        10,
        "mail.example.com",
        encoder,
        current_offset=0,
    )

    expected = (
        b"\x00\x0a"
        b"\x04mail"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    assert encoded == expected


def test_decode_mx():
    packet = (
        b"\x00\x0a"
        b"\x04mail"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    preference, exchange = DNSMXRDataCodec.decode(cursor)

    assert preference == 10
    assert str(exchange) == "mail.example.com"


def test_mx_compression():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    encoded = DNSMXRDataCodec.encode(
        20,
        "mail.example.com",
        encoder,
        current_offset=len(first),
    )

    expected = (
        b"\x00\x14"
        b"\x04mail"
        b"\xc0\x00"
    )

    assert encoded == expected


def test_invalid_mx_preference():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSRDataEncodeError):
        DNSMXRDataCodec.encode(
            -1,
            "mail.example.com",
            encoder,
            current_offset=0,
        )


# ============================================================
# TXT RDATA
# ============================================================


def test_encode_txt():
    encoded = DNSTXTRDataCodec.encode(
        ("hello", "world")
    )

    expected = (
        b"\x05hello"
        b"\x05world"
    )

    assert encoded == expected


def test_decode_txt():
    packet = (
        b"\x05hello"
        b"\x05world"
    )

    cursor = ByteCursor(packet)

    decoded = DNSTXTRDataCodec.decode(cursor)

    assert decoded == (
        "hello",
        "world",
    )


def test_encode_single_txt_string():
    encoded = DNSTXTRDataCodec.encode(
        "hello"
    )

    assert encoded == b"\x05hello"


def test_decode_single_txt_string():
    cursor = ByteCursor(
        b"\x05hello"
    )

    decoded = DNSTXTRDataCodec.decode(cursor)

    assert decoded == ("hello",)


def test_empty_txt_string():
    encoded = DNSTXTRDataCodec.encode(
        ""
    )

    assert encoded == b"\x00"


def test_txt_string_too_long():
    text = "a" * 256

    with pytest.raises(DNSRDataEncodeError):
        DNSTXTRDataCodec.encode(text)


def test_truncated_txt():
    cursor = ByteCursor(
        b"\x05hel"
    )

    with pytest.raises(DNSRDataDecodeError):
        DNSTXTRDataCodec.decode(cursor)


# ============================================================
# SOA RDATA
# ============================================================


def test_encode_soa():
    encoder = DNSCompressionEncoder()

    encoded = DNSSOARDataCodec.encode(
        "ns1.example.com",
        "hostmaster.example.com",
        2026092701,
        3600,
        600,
        86400,
        300,
        encoder,
        current_offset=0,
    )

    # ns1.example.com starts at offset 0.
    #
    # Layout:
    #
    # 00: 03 ns1
    # 04: 07 example
    # 12: 03 com
    # 16: 00
    #
    # Therefore "example.com" starts at offset 4.
    #
    # hostmaster.example.com becomes:
    #
    # 0a hostmaster c0 04
    #
    expected_names = (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
        b"\x0ahostmaster"
        b"\xc0\x04"
    )

    expected_numbers = struct.pack(
        "!IIIII",
        2026092701,
        3600,
        600,
        86400,
        300,
    )

    assert encoded == expected_names + expected_numbers


def test_decode_soa():
    packet = (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
        b"\x0ahostmaster"
        b"\xc0\x04"
        + struct.pack(
            "!IIIII",
            2026092701,
            3600,
            600,
            86400,
            300,
        )
    )

    cursor = ByteCursor(packet)

    (
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    ) = DNSSOARDataCodec.decode(cursor)

    assert str(mname) == "ns1.example.com"
    assert str(rname) == "hostmaster.example.com"

    assert serial == 2026092701
    assert refresh == 3600
    assert retry == 600
    assert expire == 86400
    assert minimum == 300

    assert cursor.at_end()


def test_soa_name_compression():
    encoder = DNSCompressionEncoder()

    # First register example.com.
    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    current_offset = len(first)

    encoded = DNSSOARDataCodec.encode(
        "ns1.example.com",
        "hostmaster.example.com",
        2026092701,
        3600,
        600,
        86400,
        300,
        encoder,
        current_offset=current_offset,
    )

    # Both names should reuse example.com.
    assert encoded.startswith(
        b"\x03ns1\xc0\x00"
    )

    assert (
        b"\x0ahostmaster\xc0\x00"
        in encoded
    )


def test_invalid_soa_serial():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSRDataEncodeError):
        DNSSOARDataCodec.encode(
            "ns1.example.com",
            "hostmaster.example.com",
            -1,
            3600,
            600,
            86400,
            300,
            encoder,
            current_offset=0,
        )


def test_invalid_soa_refresh():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSRDataEncodeError):
        DNSSOARDataCodec.encode(
            "ns1.example.com",
            "hostmaster.example.com",
            2026092701,
            -1,
            600,
            86400,
            300,
            encoder,
            current_offset=0,
        )