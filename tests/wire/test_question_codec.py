import pytest

from idns.model import DNSName, DNSQuestion
from idns.wire import (
    ByteCursor,
    DNSQuestionCodec,
    DNSQuestionDecodeError,
)


def test_encode_a_question():
    question = DNSQuestion(
        qname=DNSName("google.com"),
        qtype="A",
        qclass="IN",
    )

    encoded = DNSQuestionCodec.encode(question)

    assert encoded == bytes.fromhex(
        "06676f6f676c6503636f6d00"
        "0001"
        "0001"
    )


def test_encode_aaaa_question():
    question = DNSQuestion(
        qname=DNSName("google.com"),
        qtype="AAAA",
        qclass="IN",
    )

    encoded = DNSQuestionCodec.encode(question)

    assert encoded == bytes.fromhex(
        "06676f6f676c6503636f6d00"
        "001c"
        "0001"
    )


def test_encode_ns_question():
    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="NS",
        qclass="IN",
    )

    encoded = DNSQuestionCodec.encode(question)

    assert encoded == bytes.fromhex(
        "076578616d706c6503636f6d00"
        "0002"
        "0001"
    )


def test_decode_a_question():
    packet = bytes.fromhex(
        "06676f6f676c6503636f6d00"
        "0001"
        "0001"
    )

    question = DNSQuestionCodec.decode(
        ByteCursor(packet)
    )

    assert str(question.qname) == "google.com"
    assert question.qtype == "A"
    assert question.qclass == "IN"
    assert question.qtype_code == 1
    assert question.qclass_code == 1


def test_decode_aaaa_question():
    packet = bytes.fromhex(
        "06676f6f676c6503636f6d00"
        "001c"
        "0001"
    )

    question = DNSQuestionCodec.decode(
        ByteCursor(packet)
    )

    assert str(question.qname) == "google.com"
    assert question.qtype == "AAAA"
    assert question.qtype_code == 28
    assert question.qclass == "IN"


def test_question_round_trip():
    original = DNSQuestion(
        qname=DNSName("www.example.com"),
        qtype="A",
        qclass="IN",
    )

    encoded = DNSQuestionCodec.encode(original)

    decoded = DNSQuestionCodec.decode(
        ByteCursor(encoded)
    )

    assert str(decoded.qname) == str(original.qname)
    assert decoded.qtype == original.qtype
    assert decoded.qclass == original.qclass
    assert decoded.qtype_code == original.qtype_code
    assert decoded.qclass_code == original.qclass_code


def test_decode_truncated_qtype():
    packet = bytes.fromhex(
        "076578616d706c6503636f6d00"
    )

    cursor = ByteCursor(packet)

    with pytest.raises(DNSQuestionDecodeError):
        DNSQuestionCodec.decode(cursor)


def test_decode_truncated_qclass():
    packet = bytes.fromhex(
        "076578616d706c6503636f6d00"
        "0001"
    )

    cursor = ByteCursor(packet)

    with pytest.raises(DNSQuestionDecodeError):
        DNSQuestionCodec.decode(cursor)