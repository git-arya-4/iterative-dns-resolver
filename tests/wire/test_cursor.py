import pytest

from idns.wire import (
    ByteCursor,
    DNSBoundsError,
)


def test_read_u8():
    cursor = ByteCursor(b"\x01\x02")

    assert cursor.read_u8() == 1
    assert cursor.position == 1
    assert cursor.remaining() == 1


def test_read_u16_big_endian():
    cursor = ByteCursor(b"\x12\x34")

    assert cursor.read_u16() == 0x1234
    assert cursor.position == 2
    assert cursor.remaining() == 0


def test_read_u32_big_endian():
    cursor = ByteCursor(b"\x12\x34\x56\x78")

    assert cursor.read_u32() == 0x12345678
    assert cursor.position == 4
    assert cursor.remaining() == 0


def test_read_bytes():
    cursor = ByteCursor(b"abcdef")

    assert cursor.read_bytes(3) == b"abc"
    assert cursor.position == 3
    assert cursor.remaining() == 3


def test_skip():
    cursor = ByteCursor(b"abcdef")

    cursor.skip(3)

    assert cursor.position == 3
    assert cursor.read_u8() == ord("d")


def test_peek_does_not_advance():
    cursor = ByteCursor(b"\x10\x20")

    assert cursor.peek_u8() == 0x10
    assert cursor.position == 0
    assert cursor.remaining() == 2


def test_read_beyond_end_raises():
    cursor = ByteCursor(b"\x01")

    with pytest.raises(DNSBoundsError):
        cursor.read_u16()


def test_read_bytes_beyond_end_raises():
    cursor = ByteCursor(b"\x01\x02")

    with pytest.raises(DNSBoundsError):
        cursor.read_bytes(3)


def test_negative_size_rejected():
    cursor = ByteCursor(b"\x01")

    with pytest.raises(ValueError):
        cursor.read_bytes(-1)


def test_exact_end_is_valid():
    cursor = ByteCursor(b"\x01\x02")

    assert cursor.read_u16() == 0x0102
    assert cursor.at_end()
    assert cursor.remaining() == 0


def test_invalid_input_type_rejected():
    with pytest.raises(TypeError):
        ByteCursor("not bytes")