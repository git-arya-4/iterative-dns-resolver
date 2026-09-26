"""
DNS domain-name wire codec.

Owner: Avidipta
Phase: Phase 2
Task: 2.2

Implements basic RFC 1035 DNS name encoding and decoding.

Basic format:

    www.example.com

becomes:

    03 www 07 example 03 com 00

This task handles ordinary DNS names only.
Compression pointers are handled separately in the later
compression-related work.
"""

from __future__ import annotations

from idns.model.name import DNSName
from idns.wire.cursor import ByteCursor, DNSBoundsError


class DNSNameCodecError(Exception):
    """Base exception for DNS name codec errors."""


class DNSNameEncodeError(DNSNameCodecError):
    """Raised when a DNS name cannot be encoded."""


class DNSNameDecodeError(DNSNameCodecError):
    """Raised when DNS wire data cannot be decoded as a DNS name."""


class DNSNameCodec:
    """
    Encode and decode DNS domain names using RFC 1035 label format.

    Example:

        example.com

    becomes:

        07 example 03 com 00
    """

    MAX_LABEL_LENGTH = 63
    MAX_NAME_LENGTH = 255

    @classmethod
    def encode(cls, name: DNSName | str) -> bytes:
        """
        Encode a DNSName into DNS wire-format bytes.

        Args:
            name: Existing DNSName object or a domain-name string.

        Returns:
            DNS wire-format bytes.

        Raises:
            DNSNameEncodeError: If the name is invalid.
        """

        try:
            dns_name = name if isinstance(name, DNSName) else DNSName(name)
        except Exception as exc:
            raise DNSNameEncodeError(
                f"invalid DNS name: {name!r}"
            ) from exc

        labels = dns_name.labels

        # Root DNS name.
        if not labels:
            return b"\x00"

        encoded = bytearray()

        for label in labels:
            try:
                label_bytes = label.encode("ascii")
            except UnicodeEncodeError as exc:
                raise DNSNameEncodeError(
                    f"DNS label must contain ASCII characters: {label!r}"
                ) from exc

            if len(label_bytes) > cls.MAX_LABEL_LENGTH:
                raise DNSNameEncodeError(
                    f"DNS label exceeds 63 bytes: {label!r}"
                )

            encoded.append(len(label_bytes))
            encoded.extend(label_bytes)

        # DNS names end with a zero-length root label.
        encoded.append(0)

        if len(encoded) > cls.MAX_NAME_LENGTH:
            raise DNSNameEncodeError(
                "encoded DNS name exceeds 255 octets"
            )

        return bytes(encoded)

    @classmethod
    def decode(
        cls,
        cursor: ByteCursor,
    ) -> DNSName:
        """
        Decode a DNS name from a ByteCursor.

        This basic implementation handles ordinary labels and the
        terminating zero byte. Compression pointers are intentionally
        not handled in Task 2.2.

        Args:
            cursor: ByteCursor positioned at the beginning of a DNS name.

        Returns:
            DNSName instance.

        Raises:
            DNSNameDecodeError: If the wire representation is invalid.
        """

        labels: list[str] = []
        consumed = 0

        while True:
            try:
                length = cursor.read_u8()
            except DNSBoundsError as exc:
                raise DNSNameDecodeError(
                    "unexpected end of packet while reading DNS name"
                ) from exc

            consumed += 1

            # Zero-length label marks the root/end of the name.
            if length == 0:
                break

            # Compression pointer.
            #
            # Compression is not implemented in Task 2.2.
            if (length & 0xC0) == 0xC0:
                raise DNSNameDecodeError(
                    "DNS compression pointer encountered; "
                    "compression decoding is not part of Task 2.2"
                )

            if length > cls.MAX_LABEL_LENGTH:
                raise DNSNameDecodeError(
                    f"invalid DNS label length: {length}"
                )

            try:
                label_bytes = cursor.read_bytes(length)
            except DNSBoundsError as exc:
                raise DNSNameDecodeError(
                    "unexpected end of packet while reading DNS label"
                ) from exc

            consumed += length

            try:
                label = label_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise DNSNameDecodeError(
                    "DNS label contains non-ASCII bytes"
                ) from exc

            labels.append(label)

            if consumed > cls.MAX_NAME_LENGTH:
                raise DNSNameDecodeError(
                    "DNS name exceeds 255 octets"
                )

        try:
            if not labels:
                return DNSName(".")

            return DNSName(".".join(labels))

        except Exception as exc:
            raise DNSNameDecodeError(
                "decoded DNS name is invalid"
            ) from exc