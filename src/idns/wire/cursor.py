"""
Safe byte cursor for DNS wire-format parsing.

Owner: Avidipta
Phase: Phase 2

Provides bounds-checked sequential access to raw DNS packet bytes.
"""

from __future__ import annotations

import struct


class DNSCursorError(Exception):
    """Base exception for DNS cursor errors."""


class DNSBoundsError(DNSCursorError):
    """Raised when a read exceeds the available packet data."""


class ByteCursor:
    """
    Bounds-checked cursor over a DNS wire-format byte buffer.

    The cursor keeps track of the current offset and provides helpers
    for reading DNS primitive values in network byte order.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        self._data = memoryview(data)
        self._offset = 0

    @property
    def position(self) -> int:
        """Return the current cursor offset."""
        return self._offset

    @property
    def length(self) -> int:
        """Return the total length of the underlying buffer."""
        return len(self._data)

    def remaining(self) -> int:
        """Return the number of unread bytes."""
        return len(self._data) - self._offset

    def at_end(self) -> bool:
        """Return True when the cursor has consumed all bytes."""
        return self._offset == len(self._data)

    def ensure_available(self, size: int) -> None:
        """
        Ensure that `size` bytes can be read from the current position.

        Raises:
            ValueError: If size is negative.
            DNSBoundsError: If the requested bytes exceed the buffer.
        """
        if size < 0:
            raise ValueError("size cannot be negative")

        if size > self.remaining():
            raise DNSBoundsError(
                f"insufficient DNS packet data: "
                f"requested {size} bytes at offset {self._offset}, "
                f"but only {self.remaining()} bytes remain"
            )

    def read_bytes(self, size: int) -> bytes:
        """Read exactly `size` bytes and advance the cursor."""
        self.ensure_available(size)

        start = self._offset
        end = start + size

        self._offset = end

        return self._data[start:end].tobytes()

    def read_u8(self) -> int:
        """Read an unsigned 8-bit integer."""
        return self.read_bytes(1)[0]

    def read_u16(self) -> int:
        """Read an unsigned 16-bit big-endian integer."""
        return struct.unpack("!H", self.read_bytes(2))[0]

    def read_u32(self) -> int:
        """Read an unsigned 32-bit big-endian integer."""
        return struct.unpack("!I", self.read_bytes(4))[0]

    def peek_u8(self) -> int:
        """
        Read the next byte without advancing the cursor.

        Raises:
            DNSBoundsError: If there is no byte remaining.
        """
        self.ensure_available(1)
        return self._data[self._offset]

    def skip(self, size: int) -> None:
        """Advance the cursor by `size` bytes safely."""
        self.ensure_available(size)
        self._offset += size