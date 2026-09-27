"""
Integration tests for DNSMessageEncoder.

Phase: Phase 3
Task: 3.7
"""

from idns.model import (
    DNSHeader,
    DNSMessage,
    DNSQuestion,
    DNSName,
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)

from idns.wire.message_encoder import (
    DNSMessageEncoder,
)


# ============================================================
# HELPERS
# ============================================================


def make_header():
    return DNSHeader(
        transaction_id=0x1234,
        qr=1,
        opcode=0,
        aa=1,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        rcode=0,
        qdcount=0,
        ancount=0,
        nscount=0,
        arcount=0,
    )


# ============================================================
# EMPTY MESSAGE
# ============================================================


def test_encode_empty_message():
    message = DNSMessage(
        header=make_header(),
        questions=[],
        answers=[],
        authorities=[],
        additionals=[],
    )

    encoded = DNSMessageEncoder.encode(message)

    assert len(encoded) == 12

    # Header counts should be zero.
    assert encoded[4:12] == (
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
    )


# ============================================================
# QUESTION + A
# ============================================================


def test_encode_question_and_a():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
        qclass="IN",
    )

    answer = ARecord(
        name=DNSName("example.com"),
        address="8.8.8.8",
        ttl=300,
    )

    message = DNSMessage(
        header=make_header(),
        questions=[question],
        answers=[answer],
        authorities=[],
        additionals=[],
    )

    encoded = DNSMessageEncoder.encode(message)

    # QDCOUNT = 1
    assert encoded[4:6] == b"\x00\x01"

    # ANCOUNT = 1
    assert encoded[6:8] == b"\x00\x01"

    assert len(encoded) > 12


# ============================================================
# HEADER COUNT SYNCHRONIZATION
# ============================================================


def test_encoder_updates_header_counts():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
        qclass="IN",
    )

    answer = ARecord(
        name=DNSName("example.com"),
        address="1.2.3.4",
        ttl=100,
    )

    authority = NSRecord(
        name=DNSName("example.com"),
        nameserver=DNSName("ns1.example.com"),
        ttl=100,
    )

    additional = ARecord(
        name=DNSName("ns1.example.com"),
        address="5.6.7.8",
        ttl=100,
    )

    message = DNSMessage(
        header=make_header(),
        questions=[question],
        answers=[answer],
        authorities=[authority],
        additionals=[additional],
    )

    encoded = DNSMessageEncoder.encode(message)

    assert encoded[4:6] == b"\x00\x01"
    assert encoded[6:8] == b"\x00\x01"
    assert encoded[8:10] == b"\x00\x01"
    assert encoded[10:12] == b"\x00\x01"


# ============================================================
# ALL RECORD TYPES
# ============================================================


def test_encode_all_supported_record_types():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
        qclass="IN",
    )

    records = [
        ARecord(
            name=DNSName("example.com"),
            address="8.8.8.8",
            ttl=300,
        ),

        AAAARecord(
            name=DNSName("example.com"),
            address="2001:db8::1",
            ttl=300,
        ),

        NSRecord(
            name=DNSName("example.com"),
            nameserver=DNSName("ns1.example.com"),
            ttl=300,
        ),

        CNAMERecord(
            name=DNSName("www.example.com"),
            canonical_name=DNSName("example.com"),
            ttl=300,
        ),

        MXRecord(
            name=DNSName("example.com"),
            preference=10,
            exchange=DNSName("mail.example.com"),
            ttl=300,
        ),

        TXTRecord(
            name=DNSName("example.com"),
            text=("hello", "world"),
            ttl=300,
        ),

        SOARecord(
            name=DNSName("example.com"),
            mname=DNSName("ns1.example.com"),
            rname=DNSName("hostmaster.example.com"),
            serial=2026092701,
            refresh=3600,
            retry=600,
            expire=86400,
            minimum=300,
            ttl=300,
        ),
    ]

    message = DNSMessage(
        header=make_header(),
        questions=[question],
        answers=records,
        authorities=[],
        additionals=[],
    )

    encoded = DNSMessageEncoder.encode(message)

    assert isinstance(encoded, bytes)
    assert len(encoded) > 12

    # One question + seven answers.
    assert encoded[4:6] == b"\x00\x01"
    assert encoded[6:8] == b"\x00\x07"


# ============================================================
# ENCODE → DECODE ROUND TRIP
# ============================================================


def test_encode_decode_round_trip():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
        qclass="IN",
    )

    answer = ARecord(
        name=DNSName("example.com"),
        address="8.8.8.8",
        ttl=300,
    )

    message = DNSMessage(
        header=make_header(),
        questions=[question],
        answers=[answer],
        authorities=[],
        additionals=[],
    )

    encoded = DNSMessageEncoder.encode(message)

    from idns.wire.message_decoder import (
        DNSMessageDecoder,
    )

    decoded = DNSMessageDecoder.decode(encoded)

    assert (
        decoded.header.transaction_id
        == message.header.transaction_id
    )

    assert len(decoded.questions) == 1
    assert len(decoded.answers) == 1

    assert (
        str(decoded.questions[0].qname)
        == "example.com"
    )

    assert (
        decoded.answers[0].address
        == "8.8.8.8"
    )

    assert decoded.answers[0].ttl == 300


# ============================================================
# COMPRESSION ROUND TRIP
# ============================================================


def test_compression_round_trip():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
        qclass="IN",
    )

    answers = [
        ARecord(
            name=DNSName("example.com"),
            address="1.1.1.1",
            ttl=100,
        ),

        ARecord(
            name=DNSName("www.example.com"),
            address="2.2.2.2",
            ttl=100,
        ),

        CNAMERecord(
            name=DNSName("alias.example.com"),
            canonical_name=DNSName(
                "www.example.com"
            ),
            ttl=100,
        ),
    ]

    message = DNSMessage(
        header=make_header(),
        questions=[question],
        answers=answers,
        authorities=[],
        additionals=[],
    )

    encoded = DNSMessageEncoder.encode(message)

    # Compression should make the packet smaller than
    # encoding all names completely every time.
    assert b"\xc0" in encoded

    from idns.wire.message_decoder import (
        DNSMessageDecoder,
    )

    decoded = DNSMessageDecoder.decode(encoded)

    assert len(decoded.answers) == 3

    assert (
        str(decoded.answers[0].name)
        == "example.com"
    )

    assert (
        str(decoded.answers[1].name)
        == "www.example.com"
    )

    assert (
        str(decoded.answers[2].canonical_name)
        == "www.example.com"
    )