import pytest

from idns.wire import (
    ByteCursor,
    DNSCompressionDecoder,
    DNSCompressionDecodeError,
)


def test_decode_uncompressed_name():
    packet = (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "www.example.com"
    assert cursor.position == len(packet)


def test_decode_pointer_name():
    # Layout:
    #
    # offset 0:  03 www
    # offset 4:  C0 0C
    # offset 6:  padding
    # offset 12: 07 example
    # offset 20: 03 com
    # offset 24: 00
    #
    # C0 0C points to offset 12.

    packet = (
        b"\x03www"
        b"\xc0\x0c"
        b"\x00\x00\x00\x00\x00\x00"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "www.example.com"

    # Original cursor consumed:
    # 03 www C0 0C
    assert cursor.position == 6


def test_decode_pointer_only_name():
    # C0 02 points to offset 2.

    packet = (
        b"\xc0\x02"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "example.com"

    # Only the two-byte pointer belongs to the original name.
    assert cursor.position == 2


def test_decode_pointer_with_multiple_labels():
    # First name:
    #
    # 03 www
    # 07 example
    # 03 com
    # 00
    #
    # Second name:
    #
    # 03 api
    # C0 00
    #
    # Result:
    # api.www.example.com

    prefix = (
        b"\x03www"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    suffix = (
        b"\x03api"
        b"\xc0\x00"
    )

    packet = prefix + suffix

    cursor = ByteCursor(packet)

    cursor = cursor.fork(len(prefix))

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "api.www.example.com"


def test_pointer_out_of_bounds():
    # C0 20 points beyond the packet.

    packet = b"\xc0\x20"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)


def test_truncated_pointer():
    # C0 requires a second byte.

    packet = b"\xc0"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)


def test_invalid_reserved_label_format():
    # 10xxxxxx is reserved.
    # It is neither a normal label nor a compression pointer.

    packet = b"\x80"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)


def test_pointer_loop():
    # Pointer at offset 0 points back to itself.

    packet = b"\xc0\x00"

    cursor = ByteCursor(packet)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)


def test_two_pointer_loop():
    # offset 0 -> offset 2
    # offset 2 -> offset 0

    packet = (
        b"\xc0\x02"
        b"\xc0\x00"
    )

    cursor = ByteCursor(packet)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)


def test_compression_does_not_move_original_cursor_to_target():
    # Layout:
    #
    # offset 0:  03 www
    # offset 4:  C0 06
    # offset 6:  07 example
    # offset 14: 03 com
    # offset 18: 00
    #
    # C0 06 points to offset 6.

    packet = (
        b"\x03www"
        b"\xc0\x06"
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    cursor = ByteCursor(packet)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "www.example.com"

    # The original cursor consumed:
    #
    # 03 www C0 06
    #
    # Therefore it stops at offset 6.
    assert cursor.position == 6