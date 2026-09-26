import pytest

from idns.model import DNSHeader
from idns.wire import (
    ByteCursor,
    DNSHeaderCodec,
    DNSHeaderDecodeError,
)


def make_header():
    return DNSHeader(
        transaction_id=0x1234,
        qr=0,
        opcode=0,
        rd=1,
        qdcount=1,
    )


def test_encode_header_size():
    header = make_header()

    encoded = DNSHeaderCodec.encode(header)

    assert len(encoded) == 12


def test_encode_header():
    header = make_header()

    encoded = DNSHeaderCodec.encode(header)

    assert encoded == bytes.fromhex(
        "1234"
        "0100"
        "0001"
        "0000"
        "0000"
        "0000"
    )


def test_decode_header():
    packet = bytes.fromhex(
        "1234"
        "0100"
        "0001"
        "0000"
        "0000"
        "0000"
    )

    header = DNSHeaderCodec.decode(
        ByteCursor(packet)
    )

    assert header.transaction_id == 0x1234
    assert header.qr == 0
    assert header.opcode == 0
    assert header.rd == 1

    assert header.qdcount == 1
    assert header.ancount == 0
    assert header.nscount == 0
    assert header.arcount == 0


def test_header_round_trip():
    original = make_header()

    encoded = DNSHeaderCodec.encode(original)

    decoded = DNSHeaderCodec.decode(
        ByteCursor(encoded)
    )

    assert decoded.transaction_id == original.transaction_id
    assert decoded.qr == original.qr
    assert decoded.opcode == original.opcode
    assert decoded.aa == original.aa
    assert decoded.tc == original.tc
    assert decoded.rd == original.rd
    assert decoded.ra == original.ra
    assert decoded.rcode == original.rcode

    assert decoded.qdcount == original.qdcount
    assert decoded.ancount == original.ancount
    assert decoded.nscount == original.nscount
    assert decoded.arcount == original.arcount


def test_encode_response_header():
    header = DNSHeader(
        transaction_id=5000,
        qr=1,
        aa=1,
        ra=1,
        rcode=0,
    )

    encoded = DNSHeaderCodec.encode(header)

    decoded = DNSHeaderCodec.decode(
        ByteCursor(encoded)
    )

    assert decoded.transaction_id == 5000
    assert decoded.qr == 1
    assert decoded.aa == 1
    assert decoded.ra == 1
    assert decoded.rcode == 0


def test_all_flags():
    header = DNSHeader(
        transaction_id=0xFFFF,
        qr=1,
        opcode=15,
        aa=1,
        tc=1,
        rd=1,
        ra=1,
        rcode=15,
        qdcount=65535,
        ancount=65535,
        nscount=65535,
        arcount=65535,
    )

    encoded = DNSHeaderCodec.encode(header)

    assert len(encoded) == 12

    decoded = DNSHeaderCodec.decode(
        ByteCursor(encoded)
    )

    assert decoded.transaction_id == 0xFFFF
    assert decoded.qr == 1
    assert decoded.opcode == 15
    assert decoded.aa == 1
    assert decoded.tc == 1
    assert decoded.rd == 1
    assert decoded.ra == 1
    assert decoded.rcode == 15

    assert decoded.qdcount == 65535
    assert decoded.ancount == 65535
    assert decoded.nscount == 65535
    assert decoded.arcount == 65535


def test_decode_truncated_header():
    packet = b"\x12\x34\x01\x00"

    with pytest.raises(DNSHeaderDecodeError):
        DNSHeaderCodec.decode(
            ByteCursor(packet)
        )