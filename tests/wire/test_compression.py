import pytest

from idns.wire.cursor import ByteCursor
from idns.wire.compression import (
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
    # offset 0:  07 example
    # offset 8:  03 com
    # offset 12: 00
    # offset 13: 03 www
    # offset 17: C0 00
    #
    # C0 00 points backward to offset 0.

    packet = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        b"\x03www"
        b"\xc0\x00"
    )

    cursor = ByteCursor(packet)
    cursor.skip(13)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "www.example.com"

    # Original cursor consumed:
    # 03 www C0 00
    assert cursor.position == 19


def test_decode_pointer_only_name():
    # Layout:
    #
    # offset 0: 07 example
    # offset 8: 03 com
    # offset 12: 00
    # offset 13: C0 00
    #
    # C0 00 points backward to offset 0.

    packet = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        b"\xc0\x00"
    )

    cursor = ByteCursor(packet)
    cursor.skip(13)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "example.com"

    # Only the two-byte pointer belongs to the original name.
    assert cursor.position == 15


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
    # offset 0:  07 example
    # offset 8:  03 com
    # offset 12: 00
    # offset 13: 03 www
    # offset 17: C0 00
    #
    # C0 00 points backward to offset 0.

    packet = (
        b"\x07example"
        b"\x03com"
        b"\x00"
        b"\x03www"
        b"\xc0\x00"
    )

    cursor = ByteCursor(packet)
    cursor.skip(13)

    name = DNSCompressionDecoder.decode(cursor)

    assert str(name) == "www.example.com"

    # The original cursor consumed:
    #
    # 03 www C0 00
    #
    # Therefore it stops at offset 19.
    assert cursor.position == 19


def test_forward_pointer_rejected():
    """
    DNS compression pointers must point to an earlier
    position in the packet.
    """

    # Layout:
    #
    # 0: 03
    # 1-3: www
    # 4: c0
    # 5: 08       <- pointer target is 8
    # 6-7: unused
    # 8: 03
    # 9-11: com
    # 12: 00
    #
    # At the time the pointer is read, the cursor is at
    # offset 6, so target 8 is a forward pointer.

    data = (
        b"\x03www"
        b"\xc0\x08"
        b"\x00\x00"
        b"\x03com\x00"
    )

    cursor = ByteCursor(data)

    with pytest.raises(DNSCompressionDecodeError):
        DNSCompressionDecoder.decode(cursor)