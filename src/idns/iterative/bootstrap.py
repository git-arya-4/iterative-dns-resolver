"""Nameserver address bootstrapping for iterative resolution."""

from collections.abc import Callable

from idns.contracts.transport import (
    DNSTransportProtocol,
    TransportConfig,
)
from idns.model import ARecord, AAAARecord, DNSName


class NameserverBootstrap:
    """Resolve nameserver hostnames using the project's DNS transport."""

    def __init__(
        self,
        root_servers: list[dict[str, str]] | None = None,
        transport: DNSTransportProtocol | None = None,
        transport_config: TransportConfig | None = None,
        resolve_address: Callable[[DNSName], list[str]] | None = None,
    ) -> None:
        self.root_servers = root_servers or []
        self.transport = transport
        self.transport_config = transport_config
        self.resolve_address = resolve_address

    def resolve(
        self,
        nameserver: DNSName,
    ) -> list[str]:
        """Return addresses for a nameserver hostname."""

        if self.resolve_address is not None:
            return self.resolve_address(nameserver)

        if self.transport is None:
            raise ValueError(
                "Nameserver bootstrap requires a DNS transport "
                "when no resolver callback is provided."
            )

        if not self.root_servers:
            raise ValueError(
                "Nameserver bootstrap requires root server hints."
            )

        return self._resolve_iteratively(nameserver)

    def _resolve_iteratively(
        self,
        nameserver: DNSName,
    ) -> list[str]:
        """Resolve a nameserver hostname through the DNS hierarchy."""

        # Local imports avoid the circular dependency:
        # bootstrap -> tld_query -> bootstrap.
        from idns.iterative.root_query import RootQuery
        from idns.iterative.tld_query import TLDQuery

        root_query = RootQuery(
            root_servers=self.root_servers,
            transport=self.transport,
            transport_config=self.transport_config,
        )

        root_response, _ = root_query.query(
            nameserver.value,
            record_type="A",
        )

        addresses = self._extract_addresses(
            root_response.answers,
            nameserver,
        )

        if addresses:
            return addresses

        labels = nameserver.labels

        if len(labels) < 2:
            return []

        delegated_zone = ".".join(labels[-1:])

        tld_query = TLDQuery(
            transport=self.transport,
            transport_config=self.transport_config,
            bootstrap=None,
        )

        tld_response, _ = tld_query.query(
            root_response,
            nameserver.value,
            delegated_zone,
            record_type="A",
        )

        return self._extract_addresses(
            tld_response.answers,
            nameserver,
        )

    @staticmethod
    def _extract_addresses(
        records: list[object],
        nameserver: DNSName,
    ) -> list[str]:
        """Extract matching A and AAAA answers."""

        addresses: list[str] = []

        for record in records:
            if not isinstance(record, (ARecord, AAAARecord)):
                continue

            if record.name != nameserver:
                continue

            if record.address not in addresses:
                addresses.append(record.address)

        return addresses