"""
DNS Wire Codec Contract.

Owner: Shared Contract (Implemented by Avidipta in src/idns/wire)
Phase: Phase 0 (Contract) / Phase 2-3 (Implementation)

Defines the interface for hand-crafted RFC 1035 wire format encoding,
decoding, compression pointer handling, and binary validation.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DNSCodecProtocol(Protocol):
    """
    Protocol defining the contract for the DNS wire codec.
    
    Avidipta's wire implementation (`src/idns/wire`) must satisfy this protocol.
    It works with the internal data model (`src/idns/model`).
    """

    def encode(self, message: Any) -> bytes:
        """
        Encode a DNSMessage object into raw RFC 1035 wire bytes.
        
        Args:
            message: A DNSMessage instance from `src/idns/model`.
            
        Returns:
            bytes: The formatted binary DNS query or response packet.
            
        Raises:
            CodecError: If message fields or RDATA cannot be encoded.
        """
        ...

    def decode(self, packet: bytes) -> Any:
        """
        Decode raw RFC 1035 wire bytes into a DNSMessage object.
        
        Must handle compression pointers (0xC0 prefix) for domain names.
        
        Args:
            packet: Raw binary data received from socket or test fixture.
            
        Returns:
            DNSMessage: Parsed message object.
            
        Raises:
            CodecError: If packet is malformed, truncated, or invalid.
        """
        ...

    def validate_packet(self, packet: bytes) -> bool:
        """
        Validate whether a raw byte sequence has a valid DNS header structure.
        
        Args:
            packet: Binary buffer to inspect.
            
        Returns:
            bool: True if minimum header (12 bytes) is valid, False otherwise.
        """
        ...
