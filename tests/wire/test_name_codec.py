import pytest

from idns.model.name import DNSName
from idns.wire import (
    ByteCursor,
    DNSNameCodec,
    DNSNameDecodeError,
)


def test_encode_simple_name():
    encoded = DNSNameCodec.encode("example.com")

    assert encoded == (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_encode_subdomain():
    encoded = DNSNameCodec.encode("www.example.com")

    assert encoded == (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_encode_root():
    encoded = DNSNameCodec.encode(".")

    assert encoded == b"\x00"


def test_decode_simple_name():
    cursor = ByteCursor(
        b"\x07example\x03com\x00"
    )

    name = DNSNameCodec.decode(cursor)

    assert str(name) == "example.com"
    assert cursor.at_end()


def test_decode_subdomain():
    cursor = ByteCursor(
        b"\x03www\x07example\x03com\x00"
    )

    name = DNSNameCodec.decode(cursor)

    assert str(name) == "www.example.com"
    assert cursor.at_end()


def test_decode_root():
    cursor = ByteCursor(b"\x00")

    name = DNSNameCodec.decode(cursor)

    assert str(name) == "."
    assert cursor.at_end()


def test_encode_decode_round_trip():
    original = DNSName("www.example.com")

    encoded = DNSNameCodec.encode(original)

    decoded = DNSNameCodec.decode(
        ByteCursor(encoded)
    )

    assert decoded == original


def test_decode_invalid_label_length():
    # 64 is larger than the DNS maximum label size of 63.
    packet = b"\x40"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSNameDecodeError):
        DNSNameCodec.decode(cursor)


def test_decode_truncated_label():
    # Says the label has 3 bytes but only 2 are available.
    packet = b"\x03ab"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSNameDecodeError):
        DNSNameCodec.decode(cursor)


def test_decode_truncated_name():
    # Missing terminating zero byte.
    packet = b"\x03www"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSNameDecodeError):
        DNSNameCodec.decode(cursor)


def test_decode_rejects_compression_pointer():
    # Compression pointers are intentionally not implemented in 2.2.
    packet = b"\xc0\x0c"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSNameDecodeError):
        DNSNameCodec.decode(cursor)