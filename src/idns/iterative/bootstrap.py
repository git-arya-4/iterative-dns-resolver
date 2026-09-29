"""Nameserver address bootstrapping for iterative resolution."""

from collections.abc import Callable

from idns.model import DNSName


class NameserverBootstrap:
    """Resolve nameserver hostnames when referral glue is unavailable."""

    def __init__(
        self,
        resolve_address: Callable[[DNSName], list[str]],
    ) -> None:
        self.resolve_address = resolve_address

    def resolve(
        self,
        nameserver: DNSName,
    ) -> list[str]:
        """Return addresses for a nameserver hostname."""

        return self.resolve_address(nameserver)