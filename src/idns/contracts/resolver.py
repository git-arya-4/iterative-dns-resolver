"""
Top-Level DNS Resolver Contract.

Owner: Shared Contract (Orchestrated by Arya in idns.core, with Shriyansh/Swastik components)
Phase: Phase 0 (Contract) / Phase 5 (Implementation)

Defines abstractions for top-level resolution request processing,
resolution context tracing, CNAME loop/depth controls, and final results.
"""

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass
class ResolutionContext:
    """
    State context passed through an iterative resolution pipeline.
    
    Tracks query progression, CNAME chain traversal, and recursion depth limits
    to guarantee loop protection and depth control.
    """
    max_depth: int = 10
    current_depth: int = 0
    cname_chain: list[str] = field(default_factory=list)
    queried_servers: list[str] = field(default_factory=list)
    query_count: int = 0
    trace_log: list[str] = field(default_factory=list)

    def increment_depth(self) -> None:
        """Increment current depth and check against maximum allowed depth."""
        self.current_depth += 1
        if self.current_depth > self.max_depth:
            from idns.errors import MaxDepthExceededError
            raise MaxDepthExceededError(self.max_depth, self.current_depth)

    def record_cname(self, alias: str) -> None:
        """Record alias in CNAME chain and check for resolution loops."""
        canonical_alias = alias.strip().lower()
        if canonical_alias in self.cname_chain:
            from idns.errors import CNAMELoopError
            raise CNAMELoopError(self.cname_chain + [canonical_alias])
        self.cname_chain.append(canonical_alias)


@dataclass
class ResolverResult:
    """Encapsulates the structured outcome of a top-level resolution."""
    domain_name: str
    record_type: str
    answers: list[Any] = field(default_factory=list)
    authoritative_servers: list[Any] = field(default_factory=list)
    additional_records: list[Any] = field(default_factory=list)
    rcode: int = 0  # 0 = NOERROR, 3 = NXDOMAIN
    is_nxdomain: bool = False
    is_cache_hit: bool = False
    query_count: int = 0
    total_rtt_ms: float = 0.0
    cname_chain: list[str] = field(default_factory=list)


@runtime_checkable
class DNSResolverProtocol(Protocol):
    """
    Protocol defining the top-level DNS Resolver interface.
    
    The core resolver orchestrator (`idns.core`) satisfies this contract.
    """

    def resolve(
        self,
        domain_name: str,
        record_type: str = "A",
        context: Optional[ResolutionContext] = None,
    ) -> ResolverResult:
        """
        Perform complete DNS resolution for domain_name and record_type.
        
        Must consult local cache, perform root -> TLD -> auth iterative resolution,
        process CNAME chains, enforce loop/depth protection, and return result.
        
        Args:
            domain_name: Target FQDN to query.
            record_type: DNS record type string (A, AAAA, NS, CNAME, MX, TXT, SOA).
            context: Optional ResolutionContext for depth and loop tracking.
            
        Returns:
            ResolverResult containing answers, rcode, metrics, and records.
            
        Raises:
            ResolutionError: If resolution fails or depth/loop protection is triggered.
            DNSError: Base error for protocol/transport/cache failures.
        """
        ...
