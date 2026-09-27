"""
DNS name compression.

Owner: Avidipta
Phase: Phase 3
Tasks: 3.1, 3.2

Implements RFC 1035 DNS name compression-pointer decoding
and generation.

Compression pointer format:

    11xxxxxx xxxxxxxx

The lower 14 bits represent an offset into the DNS packet.
"""

from __future__ import annotations

from idns.model import DNSName
from idns.wire.cursor import (
    ByteCursor,
    DNSBoundsError,
)


class DNSCompressionError(Exception):
    """Base exception for DNS compression errors."""


class DNSCompressionDecodeError(DNSCompressionError):
    """Raised when a compressed DNS name cannot be decoded."""


class DNSCompressionEncodeError(DNSCompressionError):
    """Raised when a DNS name cannot be compressed/encoded."""


class DNSCompressionDecoder:
    """
    Decode DNS names containing RFC 1035 compression pointers.
    """

    MAX_LABEL_LENGTH = 63
    MAX_NAME_LENGTH = 255
    MAX_POINTER_DEPTH = 16

    @classmethod
    def decode(cls, cursor: ByteCursor) -> DNSName:
        """
        Decode a DNS name from the current cursor position.

        Compression pointers are followed using a forked cursor.
        """

        if not isinstance(cursor, ByteCursor):
            raise DNSCompressionDecodeError(
                "cursor must be a ByteCursor"
            )

        labels: list[str] = []
        visited_offsets: set[int] = set()
        pointer_depth = 0
        expanded_length = 1

        current = cursor

        while True:
            try:
                first = current.read_u8()
            except DNSBoundsError as exc:
                raise DNSCompressionDecodeError(
                    "unexpected end of packet while decoding DNS name"
                ) from exc

            # Root / terminating label
            if first == 0:
                break

            # Compression pointer
            if (first & 0xC0) == 0xC0:
                try:
                    second = current.read_u8()
                except DNSBoundsError as exc:
                    raise DNSCompressionDecodeError(
                        "truncated DNS compression pointer"
                    ) from exc

                pointer = (
                        ((first & 0x3F) << 8)
                        | second
                )

                # Compression pointers must reference an earlier
                # occurrence in the DNS packet. A pointer to its
                # own position or to a later position is invalid.
                if pointer >= current.position:
                    raise DNSCompressionDecodeError(
                        f"forward compression pointer is invalid: "
                        f"{pointer} >= {current.position}"
                    )

                if pointer >= cursor.length:
                    raise DNSCompressionDecodeError(
                        f"compression pointer out of bounds: {pointer}"
                    )

                if pointer in visited_offsets:
                    raise DNSCompressionDecodeError(
                        f"compression pointer loop detected at offset {pointer}"
                    )

                visited_offsets.add(pointer)

                pointer_depth += 1

                if pointer_depth > cls.MAX_POINTER_DEPTH:
                    raise DNSCompressionDecodeError(
                        "maximum DNS compression pointer depth exceeded"
                    )

                current = cursor.fork(pointer)

                continue

            # Reserved label format
            if (first & 0xC0) != 0:
                raise DNSCompressionDecodeError(
                    f"invalid DNS label/pointer byte: 0x{first:02x}"
                )

            # Ordinary label
            label_length = first

            if label_length > cls.MAX_LABEL_LENGTH:
                raise DNSCompressionDecodeError(
                    f"invalid DNS label length: {label_length}"
                )

            try:
                label_bytes = current.read_bytes(label_length)
            except DNSBoundsError as exc:
                raise DNSCompressionDecodeError(
                    "unexpected end of packet while reading DNS label"
                ) from exc

            try:
                label = label_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise DNSCompressionDecodeError(
                    "DNS label contains non-ASCII bytes"
                ) from exc

            labels.append(label)

            expanded_length += 1 + label_length

            if expanded_length > cls.MAX_NAME_LENGTH:
                raise DNSCompressionDecodeError(
                    "expanded DNS name exceeds 255 octets"
                )

        try:
            if not labels:
                return DNSName(".")

            return DNSName(".".join(labels))

        except ValueError as exc:
            raise DNSCompressionDecodeError(
                "decoded compressed DNS name is invalid"
            ) from exc


class DNSCompressionEncoder:
    """
    Generate DNS names using RFC 1035 compression pointers.

    The encoder maintains a table of previously written suffixes.

    Example:

        Existing packet:

            03 www 07 example 03 com 00

        New name:

            api.example.com

        can become:

            03 api C0 04

        where C0 04 points to "example.com".
    """

    MAX_POINTER_OFFSET = 0x3FFF
    MAX_NAME_LENGTH = 255
    MAX_LABEL_LENGTH = 63

    def __init__(self):
        """
        Create a new compression encoder.

        The compression table maps a DNS suffix to the byte offset
        where that suffix begins in the packet.
        """

        self._suffix_offsets: dict[str, int] = {}

    @property
    def suffix_offsets(self) -> dict[str, int]:
        """
        Return a copy of the current compression table.
        """

        return dict(self._suffix_offsets)

    def encode(
        self,
        name: DNSName | str,
        current_offset: int,
    ) -> bytes:
        """
        Encode a DNS name using previously registered suffixes.

        Args:
            name:
                DNSName or domain-name string.

            current_offset:
                Absolute packet offset where this name will be written.

        Returns:
            Encoded DNS name bytes.

        Raises:
            DNSCompressionEncodeError:
                If the name or offset is invalid.
        """

        try:
            dns_name = (
                name
                if isinstance(name, DNSName)
                else DNSName(name)
            )
        except Exception as exc:
            raise DNSCompressionEncodeError(
                f"invalid DNS name: {name!r}"
            ) from exc

        if current_offset < 0:
            raise DNSCompressionEncodeError(
                "current offset cannot be negative"
            )

        if current_offset > self.MAX_POINTER_OFFSET:
            raise DNSCompressionEncodeError(
                "current offset exceeds DNS compression pointer range"
            )

        labels = dns_name.labels

        # Root name.
        if not labels:
            return b"\x00"

        # Find the longest suffix already present.
        pointer_index = None
        pointer_offset = None

        for index in range(len(labels)):
            suffix = ".".join(labels[index:]).lower()

            if suffix in self._suffix_offsets:
                offset = self._suffix_offsets[suffix]

                if 0 <= offset <= self.MAX_POINTER_OFFSET:
                    pointer_index = index
                    pointer_offset = offset
                    break

        encoded = bytearray()
        write_offset = current_offset

        # Write labels before the pointer.
        limit = (
            pointer_index
            if pointer_index is not None
            else len(labels)
        )

        for index in range(limit):
            label = labels[index]

            try:
                label_bytes = label.encode("ascii")
            except UnicodeEncodeError as exc:
                raise DNSCompressionEncodeError(
                    f"DNS label must contain ASCII characters: {label!r}"
                ) from exc

            if len(label_bytes) > self.MAX_LABEL_LENGTH:
                raise DNSCompressionEncodeError(
                    f"DNS label exceeds 63 bytes: {label!r}"
                )

            suffix = ".".join(labels[index:]).lower()

            # Register this suffix at its absolute packet offset.
            if write_offset <= self.MAX_POINTER_OFFSET:
                self._suffix_offsets.setdefault(
                    suffix,
                    write_offset,
                )

            encoded.append(len(label_bytes))
            encoded.extend(label_bytes)

            write_offset += 1 + len(label_bytes)

        # Use a compression pointer if a suffix was found.
        if pointer_index is not None:
            assert pointer_offset is not None

            pointer_value = (
                0xC000 | pointer_offset
            )

            encoded.extend(
                pointer_value.to_bytes(2, "big")
            )

            return bytes(encoded)

        # No suffix found.
        #
        # Register the complete name before writing the terminating
        # root label.
        full_name = ".".join(labels).lower()

        if write_offset <= self.MAX_POINTER_OFFSET:
            self._suffix_offsets.setdefault(
                full_name,
                write_offset,
            )

        encoded.append(0)

        if len(encoded) > self.MAX_NAME_LENGTH:
            raise DNSCompressionEncodeError(
                "encoded DNS name exceeds 255 octets"
            )

        return bytes(encoded)