"""
Error hierarchy for the Iterative DNS Resolver project.

All exceptions inherit from `DNSError` to allow clean top-level catching.
Subsystem-specific exceptions map to team module responsibilities.
"""

from typing import Optional


class DNSError(Exception):
    """Base exception for all Iterative DNS Resolver errors."""
    def __init__(self, message: str, cause: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.cause = cause


class ConfigError(DNSError):
    """Raised when configuration or root hints files are invalid/missing."""
    pass


class CodecError(DNSError):
    """Raised during wire format encoding/decoding or message parsing errors."""
    pass


class TransportError(DNSError):
    """Base class for network and socket transport failures."""
    pass


class DNSTimeoutError(TransportError):
    """Raised when a DNS query times out across retries."""
    def __init__(self, server: str, timeout: float, message: Optional[str] = None):
        msg = message or f"DNS query to server '{server}' timed out after {timeout} seconds."
        super().__init__(msg)
        self.server = server
        self.timeout = timeout


class ServerUnreachableError(TransportError):
    """Raised when all candidate DNS servers are unreachable or fail to respond."""
    pass


class ResolutionError(DNSError):
    """Base class for iterative resolution logical errors."""
    pass


class CNAMELoopError(ResolutionError):
    """Raised when a CNAME resolution loop is detected."""
    def __init__(self, cname_chain: list[str]):
        msg = f"CNAME loop detected in chain: {' -> '.join(cname_chain)}"
        super().__init__(msg)
        self.cname_chain = cname_chain


class MaxDepthExceededError(ResolutionError):
    """Raised when CNAME or referral recursion exceeds maximum allowed depth."""
    def __init__(self, max_depth: int, current_depth: int):
        msg = f"Maximum resolution depth ({max_depth}) exceeded at depth {current_depth}."
        super().__init__(msg)
        self.max_depth = max_depth
        self.current_depth = current_depth


class ReferralError(ResolutionError):
    """Raised when a referral response is invalid or missing required glue/NS info."""
    pass


class CacheError(DNSError):
    """Raised during cache storage or retrieval failures."""
    pass


class ServerError(DNSError):
    """Raised during local DNS server setup or client handling failures."""
    pass
