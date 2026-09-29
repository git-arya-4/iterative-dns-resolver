"""Nameserver address bootstrapping for iterative resolution."""

from collections.abc import Callable

from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
)
from idns.iterative.authoritative_query import AuthoritativeQuery
from idns.iterative.delegation import DelegationTracker
from idns.iterative.glue import GlueExtractor
from idns.iterative.referral import ReferralParser
from idns.model import ARecord, AAAARecord, DNSMessage, DNSName, NSRecord


class NameserverBootstrap:
    """Resolve nameserver hostnames using the project's iterative DNS transport."""

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
        self._resolving: set[DNSName] = set()

    def resolve(self, nameserver: DNSName) -> list[str]:
        """Resolve a nameserver hostname to IPv4 and IPv6 addresses."""
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

        if nameserver in self._resolving:
            raise ValueError(
                f"Nameserver bootstrap recursion detected for {nameserver.value}."
            )

        self._resolving.add(nameserver)

        try:
            addresses: list[str] = []

            for record_type in ("A", "AAAA"):
                resolved = self._resolve_iteratively(
                    nameserver,
                    record_type,
                )

                for address in resolved:
                    if address not in addresses:
                        addresses.append(address)

            return addresses
        finally:
            self._resolving.remove(nameserver)

    def _resolve_iteratively(
        self,
        nameserver: DNSName,
        record_type: str,
    ) -> list[str]:
        from idns.iterative.root_query import RootQuery
        from idns.iterative.tld_query import TLDQuery

        root_query = RootQuery(
            root_servers=self.root_servers,
            transport=self.transport,
            transport_config=self.transport_config,
        )

        root_response, _ = root_query.query(
            nameserver.value,
            record_type=record_type,
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

        tld_zone = ".".join(labels[-1:])

        tld_query = TLDQuery(
            transport=self.transport,
            transport_config=self.transport_config,
            bootstrap=self,
        )

        tld_response, _ = tld_query.query(
            root_response,
            nameserver.value,
            tld_zone,
            record_type=record_type,
        )

        addresses.extend(
            self._extract_addresses(
                tld_response.answers,
                nameserver,
            )
        )

        if addresses:
            return addresses

        delegated_zone = ".".join(labels[-2:])
        tracker = DelegationTracker()
        current_response = tld_response
        current_zone = delegated_zone

        while True:
            referral_nameservers = ReferralParser.select_nameservers(
                current_response,
                current_zone,
            )

            if not referral_nameservers:
                return addresses

            tracker.record_referral(
                current_zone,
                referral_nameservers,
            )

            glue = GlueExtractor.extract(
                current_response,
                referral_nameservers,
            )

            authoritative_query = AuthoritativeQuery(
                transport=self.transport,
                transport_config=self.transport_config,
            )

            next_response: DNSMessage | None = None
            progressed = False

            for referral_nameserver in referral_nameservers:
                server_addresses = glue.get(referral_nameserver, [])

                if not server_addresses:
                    try:
                        server_addresses = self.resolve(referral_nameserver)
                    except ValueError:
                        server_addresses = []

                for address in server_addresses:
                    server = ServerAddress(
                        ip=address,
                        port=53,
                        protocol="UDP",
                        name=referral_nameserver.value,
                    )

                    authoritative_response, _ = authoritative_query.query(
                        server,
                        nameserver.value,
                        record_type=record_type,
                    )

                    addresses.extend(
                        self._extract_addresses(
                            authoritative_response.answers,
                            nameserver,
                        )
                    )

                    if addresses:
                        return addresses

                    referral_zone = self._select_delegated_zone(
                        authoritative_response,
                        nameserver,
                        current_zone,
                    )

                    if referral_zone is not None:
                        next_response = authoritative_response
                        current_zone = referral_zone
                        progressed = True
                        break

                if progressed:
                    break

            if not progressed or next_response is None:
                return addresses

            current_response = next_response

    @staticmethod
    def _select_delegated_zone(
        response: DNSMessage,
        nameserver: DNSName,
        current_zone: str,
    ) -> str | None:
        """Select the most specific referral zone below the current zone."""
        current = DNSName(current_zone)
        candidates: list[DNSName] = []

        for record in response.authorities:
            if not isinstance(record, NSRecord):
                continue

            zone = record.name

            if zone == current:
                continue

            if len(zone.labels) <= len(current.labels):
                continue

            if len(nameserver.labels) < len(zone.labels):
                continue

            if nameserver.labels[-len(zone.labels):] != zone.labels:
                continue

            if zone not in candidates:
                candidates.append(zone)

        if not candidates:
            return None

        candidates.sort(key=lambda zone: len(zone.labels), reverse=True)
        return candidates[0].value

    @staticmethod
    def _extract_addresses(
        records: list[object],
        nameserver: DNSName,
    ) -> list[str]:
        """Extract matching A and AAAA records without duplicates."""
        addresses: list[str] = []

        for record in records:
            if not isinstance(record, (ARecord, AAAARecord)):
                continue

            if record.name != nameserver:
                continue

            if record.address not in addresses:
                addresses.append(record.address)

        return addresses