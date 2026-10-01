"""Core resolver orchestration subsystem.

Owner: Arya
Phase: Production core integration

Responsibilities:
- Coordinates cache lookups (Swastik) and iterative queries (Shriyansh)
- Handles CNAME alias processing and loop/depth protection
- Manages Root hints loading and resolution context
- Provides high-level resolver instantiation for server mode and CLI
"""

import json
import ipaddress
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
from idns.contracts.transport import TransportConfig
from idns.errors import ConfigError


SUPPORTED_RECORD_TYPES = frozenset({"A", "AAAA", "NS", "CNAME", "MX", "TXT", "SOA"})


class CoreResolver(DNSResolverProtocol):
    """
    Production orchestration layer for the cache-aware iterative resolver.
    """

    def __init__(
        self,
        root_hints_path: Optional[str | Path] = None,
        codec: Optional[DNSCodecProtocol] = None,
        transport: Optional[DNSTransportProtocol] = None,
        cache: Optional[DNSCacheProtocol] = None,
        transport_config: Optional[TransportConfig] = None,
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
                transport_config=transport_config,
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
            if not isinstance(data, dict):
                raise ConfigError(f"Root hints document must be an object: {file_path}")
            self.root_servers = data.get("root_servers", [])
            if not self.root_servers:
                raise ConfigError(f"No root servers defined in: {file_path}")
            if not isinstance(self.root_servers, list):
                raise ConfigError(f"root_servers must be a list: {file_path}")
            for index, server in enumerate(self.root_servers):
                if not isinstance(server, dict) or not isinstance(server.get("name"), str):
                    raise ConfigError(f"Malformed root server entry at index {index}")
                addresses = [server.get("ipv4"), server.get("ipv6")]
                if not any(isinstance(address, str) and address for address in addresses):
                    raise ConfigError(f"Root server '{server['name']}' has no address")
                for address in addresses:
                    if address:
                        try:
                            ipaddress.ip_address(address)
                        except ValueError as exc:
                            raise ConfigError(
                                f"Invalid address '{address}' for root server '{server['name']}'",
                                cause=exc,
                            ) from exc
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

        from idns.model import DNSName
        try:
            DNSName(domain_name)
        except (ValueError, UnicodeError) as exc:
            from idns.errors import ResolutionError
            raise ResolutionError(f"Invalid domain name: '{domain_name}'", cause=exc) from exc

        if not isinstance(record_type, str) or not record_type.strip():
            from idns.errors import ResolutionError
            raise ResolutionError(f"Invalid record type: '{record_type}'")

        record_type = record_type.upper().strip()
        if record_type not in SUPPORTED_RECORD_TYPES:
            from idns.errors import ResolutionError
            raise ResolutionError(f"Unsupported record type: '{record_type}'")

        if not self.resolver_chain:
            raise ConfigError("Resolver chain not initialized. Cache or iterative engine missing.")

        return self.resolver_chain.resolve(domain_name, record_type, context)


# Backwards-compatible name retained for callers from the foundation phase.
CoreResolverScaffold = CoreResolver

__all__ = ["CoreResolver", "CoreResolverScaffold"]
