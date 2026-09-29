"""Nameserver address bootstrapping for iterative resolution."""

import socket
from collections.abc import Callable

from idns.model import DNSName


class NameserverBootstrap:
    """Resolve nameserver hostnames when referral glue is unavailable."""

    def __init__(
        self,
        resolve_address: Callable[[DNSName], list[str]] | None = None,
    ) -> None:
        self.resolve_address = (
            resolve_address
            if resolve_address is not None
            else self._resolve_with_system_dns
        )

    def resolve(
        self,
        nameserver: DNSName,
    ) -> list[str]:
        """Return addresses for a nameserver hostname."""

        return self.resolve_address(nameserver)

    @staticmethod
    def _resolve_with_system_dns(
        nameserver: DNSName,
    ) -> list[str]:
        """Resolve a nameserver hostname using the system resolver."""

        hostname = nameserver.value.rstrip(".")

        addresses: list[str] = []

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(
                    hostname,
                    53,
                    family=family,
                    type=socket.SOCK_DGRAM,
                )
            except socket.gaierror:
                continue

            for result in results:
                address = result[4][0]

                if address not in addresses:
                    addresses.append(address)

        return addresses