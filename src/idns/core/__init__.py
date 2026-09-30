"""
Core Resolver Orchestration Subsystem.

Owner: Arya
Phase: Phase 0 (Foundation) & Phase 5 (Core Resolver Integration)

Responsibilities:
- Coordinates cache lookups (Swastik) and iterative queries (Shriyansh)
- Handles CNAME alias processing and loop/depth protection
- Manages Root hints loading and resolution context
- Provides high-level resolver instantiation for server mode and CLI
"""

import json
from pathlib import Path
from typing import Optional

from idns.contracts.cache import DNSCacheProtocol
from idns.contracts.codec import DNSCodecProtocol
from idns.contracts.resolver import (
    DNSResolverProtocol,
    ResolutionContext,
    ResolverResult,
)
from idns.contracts.transport import DNSTransportProtocol
from idns.errors import ConfigError


class CoreResolverScaffold(DNSResolverProtocol):
    """
    Foundation scaffold for the Core DNS Resolver.
    
    Acts as the orchestration layer between cache, iterative resolution engine,
    and CNAME processor. Full resolution logic will be integrated in Phase 5.
    """

    def __init__(
        self,
        root_hints_path: Optional[str | Path] = None,
        codec: Optional[DNSCodecProtocol] = None,
        transport: Optional[DNSTransportProtocol] = None,
        cache: Optional[DNSCacheProtocol] = None,
    ):
        self.codec = codec
        self.transport = transport
        self.cache = cache
        self.root_servers: list[dict[str, str]] = []
        
        if root_hints_path:
            self.load_root_hints(root_hints_path)

        self.resolver_chain: Optional[DNSResolverProtocol] = None
        if self.transport and self.cache:
            from idns.iterative.engine import IterativeEngine
            from idns.core.cache_aware import CacheAwareResolver

            iterative_engine = IterativeEngine(
                transport=self.transport,
                root_servers=self.root_servers,
            )
            self.resolver_chain = CacheAwareResolver(
                cache=self.cache,
                iterative_resolver=iterative_engine,
            )

    def create_context(
        self,
        context: Optional[ResolutionContext] = None,
    ) -> ResolutionContext:
        """Return the supplied context or create a fresh resolution context."""
        return context if context is not None else ResolutionContext()

    def load_root_hints(self, path: str | Path) -> list[dict[str, str]]:
        """Load and validate root hints configuration from JSON file."""
        file_path = Path(path)
        if not file_path.is_file():
            raise ConfigError(f"Root hints file not found at: {file_path}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.root_servers = data.get("root_servers", [])
            if not self.root_servers:
                raise ConfigError(f"No root servers defined in: {file_path}")
            return self.root_servers
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in root hints file '{file_path}': {e}", cause=e)

    def resolve(
        self,
        domain_name: str,
        record_type: str = "A",
        context: Optional[ResolutionContext] = None,
    ) -> ResolverResult:
        """
        Final entry point for domain resolution (Task 5.8).
        Validates input and delegates to the configured cache-aware resolver chain.
        """
        if not isinstance(domain_name, str) or not domain_name.strip():
            from idns.errors import ResolutionError
            raise ResolutionError(f"Invalid domain name: '{domain_name}'")

        if not isinstance(record_type, str) or not record_type.strip():
            from idns.errors import ResolutionError
            raise ResolutionError(f"Invalid record type: '{record_type}'")

        record_type = record_type.upper().strip()

        if not self.resolver_chain:
            raise ConfigError("Resolver chain not initialized. Cache or iterative engine missing.")

        return self.resolver_chain.resolve(domain_name, record_type, context)


__all__ = ["CoreResolverScaffold"]
