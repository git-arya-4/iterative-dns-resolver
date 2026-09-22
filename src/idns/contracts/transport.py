"""
DNS Socket Transport Contract.

Owner: Shared Contract (Implemented by Shriyansh in src/idns/transport)
Phase: Phase 0 (Contract) / Phase 2-3 (Implementation)

Defines abstractions for low-level UDP socket queries, timeout, retry,
candidate server selection, and automatic TCP fallback when TC=1.
"""

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class ServerAddress:
    """Represents a candidate DNS server network endpoint."""
    ip: str
    port: int = 53
    protocol: str = "UDP"  # "UDP" or "TCP"
    name: Optional[str] = None


@dataclass
class TransportConfig:
    """Configuration for socket transport execution."""
    timeout_seconds: float = 2.0
    max_retries: int = 3
    enable_tcp_fallback: bool = True
    buffer_size: int = 512  # Standard RFC 1035 UDP limit


@dataclass
class TransportResult:
    """Encapsulates the raw outcome of a network transport query."""
    raw_response: bytes
    server_used: ServerAddress
    rtt_ms: float
    tc_bit_set: bool = False
    is_tcp: bool = False


@runtime_checkable
class DNSTransportProtocol(Protocol):
    """
    Protocol defining socket transport behavior.
    
    Shriyansh's transport module (`src/idns/transport`) must satisfy this protocol.
    """

    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config: Optional[TransportConfig] = None,
    ) -> TransportResult:
        """
        Transmit raw DNS query bytes to a target server over UDP (with TCP fallback if TC=1).
        
        Args:
            server: Target IP and port endpoint.
            query_bytes: Raw DNS message bytes encoded by codec.
            config: Optional timeout, retry, and buffer settings.
            
        Returns:
            TransportResult containing raw response bytes, RTT, and server info.
            
        Raises:
            DNSTimeoutError: If all retry attempts time out.
            ServerUnreachableError: If socket connection / send fails.
            TransportError: For general transport failures.
        """
        ...
