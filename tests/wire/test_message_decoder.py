"""
Integration tests for DNSMessageDecoder.

Phase: Phase 3
Task: 3.6
"""

import struct

import pytest

from idns.model import (
    DNSHeader,
    DNSMessage,
)

from idns.wire.message_decoder import (
    DNSMessageDecoder,
    DNSMessageDecodeError,
    DNSUnsupportedRecordTypeError,
)


# ============================================================
# HELPERS
# ============================================================


def make_header(
    qdcount=0,
    ancount=0,
    nscount=0,
    arcount=0,
):
    return struct.pack(
        "!HHHHHH",
        0x1234,  # transaction ID
        0x8000,  # QR = response
        qdcount,
        ancount,
        nscount,
        arcount,
    )


def a_record(
    name=b"\x07example\x03com\x00",
    address=b"\x08\x08\x08\x08",
    ttl=300,
):
    return (
        name
        + struct.pack(
            "!HHIH",
            1,       # TYPE A
            1,       # CLASS IN
            ttl,
            4,
        )
        + address
    )


# ============================================================
# BASIC MESSAGE
# ============================================================


def test_decode_empty_dns_message():
    packet = make_header()

    message = DNSMessageDecoder.decode(packet)

    assert message.header.transaction_id == 0x1234

    assert len(message.questions) == 0
    assert len(message.answers) == 0
    assert len(message.authorities) == 0
    assert len(message.additionals) == 0


# ============================================================
# QUESTION + A ANSWER
# ============================================================


def test_decode_question_and_a_answer():
    header = make_header(
        qdcount=1,
        ancount=1,
    )

    question = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HH",
            1,  # A
            1,  # IN
        )
    )

    answer = (
        b"\xc0\x0c"
        + struct.pack(
            "!HHIH",
            1,       # A
            1,       # IN
            300,
            4,
        )
        + b"\x08\x08\x08\x08"
    )

    packet = header + question + answer

    message = DNSMessageDecoder.decode(packet)

    assert len(message.questions) == 1
    assert len(message.answers) == 1

    assert str(message.questions[0].qname) == "example.com"

    record = message.answers[0]

    assert str(record.name) == "example.com"
    assert record.address == "8.8.8.8"
    assert record.ttl == 300


# ============================================================
# CNAME
# ============================================================


def test_decode_cname_answer():
    header = make_header(
        qdcount=1,
        ancount=1,
    )

    question = (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack("!HH", 1, 1)
    )

    answer = (
        b"\xc0\x0c"
        + struct.pack(
            "!HHIH",
            5,  # CNAME
            1,
            300,
            9,
        )
        + (
            b"\x06google"
            b"\xc0\x10"
        )
    )

    packet = header + question + answer

    message = DNSMessageDecoder.decode(packet)

    assert len(message.answers) == 1

    record = message.answers[0]

    assert str(record.name) == "www.example.com"
    assert str(record.canonical_name) == "google.example.com"


# ============================================================
# NS + ADDITIONAL A
# ============================================================


def test_decode_ns_and_additional_a():
    header = make_header(
        qdcount=1,
        ancount=1,
        arcount=1,
    )

    question = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack("!HH", 2, 1)
    )

    ns_rdata = (
        b"\x02ns"
        b"\xc0\x0c"
    )

    answer = (
        b"\xc0\x0c"
        + struct.pack(
            "!HHIH",
            2,  # NS
            1,
            300,
            len(ns_rdata),
        )
        + ns_rdata
    )

    additional = (
        b"\x02ns"
        b"\xc0\x0c"
        + struct.pack(
            "!HHIH",
            1,
            1,
            300,
            4,
        )
        + b"\x01\x02\x03\x04"
    )

    packet = header + question + answer + additional

    message = DNSMessageDecoder.decode(packet)

    assert len(message.answers) == 1
    assert len(message.additionals) == 1

    ns = message.answers[0]

    assert str(ns.name) == "example.com"
    assert str(ns.nameserver) == "ns.example.com"

    additional_a = message.additionals[0]

    assert additional_a.address == "1.2.3.4"


# ============================================================
# MX
# ============================================================


def test_decode_mx():
    header = make_header(
        ancount=1,
    )

    exchange = (
        b"\x04mail"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    answer = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            15,  # MX
            1,
            600,
            2 + len(exchange),
        )
        + struct.pack("!H", 10)
        + exchange
    )

    message = DNSMessageDecoder.decode(
        header + answer
    )

    record = message.answers[0]

    assert record.preference == 10
    assert str(record.exchange) == "mail.example.com"


# ============================================================
# TXT
# ============================================================


def test_decode_txt():
    header = make_header(
        ancount=1,
    )

    rdata = (
        b"\x05hello"
        b"\x05world"
    )

    answer = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            16,  # TXT
            1,
            300,
            len(rdata),
        )
        + rdata
    )

    message = DNSMessageDecoder.decode(
        header + answer
    )

    record = message.answers[0]

    assert record.text == (
        "hello",
        "world",
    )


# ============================================================
# SOA
# ============================================================


def test_decode_soa():
    header = make_header(
        nscount=1,
    )

    mname = (
        b"\x03ns1"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    rname = (
        b"\x0ahostmaster"
        b"\xc0\x0c"
    )

    numbers = struct.pack(
        "!IIIII",
        2026092701,
        3600,
        600,
        86400,
        300,
    )

    rdata = mname + rname + numbers

    record = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            6,  # SOA
            1,
            3600,
            len(rdata),
        )
        + rdata
    )

    message = DNSMessageDecoder.decode(
        header + record
    )

    soa = message.authorities[0]

    assert str(soa.mname) == "ns1.example.com"
    assert str(soa.rname) == "hostmaster.example.com"

    assert soa.serial == 2026092701
    assert soa.refresh == 3600
    assert soa.retry == 600
    assert soa.expire == 86400
    assert soa.minimum == 300


# ============================================================
# AAAA
# ============================================================


def test_decode_aaaa():
    header = make_header(
        ancount=1,
    )

    address = bytes.fromhex(
        "20010db8000000000000000000000001"
    )

    record = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            28,
            1,
            300,
            16,
        )
        + address
    )

    message = DNSMessageDecoder.decode(
        header + record
    )

    decoded = message.answers[0]

    assert decoded.address == "2001:db8::1"


# ============================================================
# INVALID PACKET
# ============================================================


def test_decode_truncated_header():
    with pytest.raises(DNSMessageDecodeError):
        DNSMessageDecoder.decode(
            b"\x00\x01"
        )


def test_decode_truncated_rdata():
    header = make_header(
        ancount=1,
    )

    record = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            1,
            1,
            300,
            4,
        )
        + b"\x08\x08"
    )

    with pytest.raises(DNSMessageDecodeError):
        DNSMessageDecoder.decode(
            header + record
        )


def test_decode_unsupported_record_type():
    header = make_header(
        ancount=1,
    )

    record = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        + struct.pack(
            "!HHIH",
            99,
            1,
            300,
            0,
        )
    )

    with pytest.raises(
        DNSUnsupportedRecordTypeError
    ):
        DNSMessageDecoder.decode(
            header + record
        )