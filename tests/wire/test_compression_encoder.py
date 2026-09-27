import pytest

from idns.model import DNSName
from idns.wire import (
    DNSCompressionEncoder,
    DNSCompressionEncodeError,
)


def test_encode_first_name_without_pointer():
    encoder = DNSCompressionEncoder()

    encoded = encoder.encode(
        "example.com",
        current_offset=0,
    )

    assert encoded == (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_encode_second_name_using_pointer():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    assert first == (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    second = encoder.encode(
        "www.example.com",
        current_offset=len(first),
    )

    assert second == (
        b"\x03www"
        b"\xc0\x00"
    )


def test_encode_shared_suffix():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    second_offset = len(first)

    second = encoder.encode(
        "mail.example.com",
        current_offset=second_offset,
    )

    assert second == (
        b"\x04mail"
        b"\xc0\x00"
    )


def test_encode_multiple_shared_suffixes():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "example.com",
        current_offset=0,
    )

    second = encoder.encode(
        "www.example.com",
        current_offset=len(first),
    )

    third_offset = len(first) + len(second)

    third = encoder.encode(
        "api.example.com",
        current_offset=third_offset,
    )

    assert third == (
        b"\x03api"
        b"\xc0\x00"
    )


def test_encode_root():
    encoder = DNSCompressionEncoder()

    encoded = encoder.encode(
        ".",
        current_offset=0,
    )

    assert encoded == b"\x00"


def test_encode_dnsname_object():
    encoder = DNSCompressionEncoder()

    name = DNSName("example.com")

    encoded = encoder.encode(
        name,
        current_offset=0,
    )

    assert encoded == (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )


def test_case_insensitive_suffix_matching():
    encoder = DNSCompressionEncoder()

    first = encoder.encode(
        "Example.COM",
        current_offset=0,
    )

    assert first == (
        b"\x07Example"
        b"\x03COM"
        b"\x00"
    )

    second = encoder.encode(
        "www.example.com",
        current_offset=len(first),
    )

    assert second == (
        b"\x03www"
        b"\xc0\x00"
    )


def test_invalid_negative_offset():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSCompressionEncodeError):
        encoder.encode(
            "example.com",
            current_offset=-1,
        )


def test_offset_above_pointer_limit():
    encoder = DNSCompressionEncoder()

    with pytest.raises(DNSCompressionEncodeError):
        encoder.encode(
            "example.com",
            current_offset=0x4000,
        )


def test_suffix_table_is_not_exposed_directly():
    encoder = DNSCompressionEncoder()

    encoder.encode(
        "example.com",
        current_offset=0,
    )

    table = encoder.suffix_offsets

    table["example.com"] = 999

    assert encoder.suffix_offsets["example.com"] == 0