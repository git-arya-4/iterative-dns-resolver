"""TLD-server query support for iterative DNS resolution."""

from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.iterative.bootstrap import NameserverBootstrap
from idns.iterative.glue import GlueExtractor
from idns.iterative.referral import ReferralParser
from idns.model import DNSHeader, DNSMessage, DNSName, DNSQuestion
from idns.wire.message_decoder import DNSMessageDecoder
from idns.wire.message_encoder import DNSMessageEncoder


class TLDQuery:
    """Query TLD nameservers using referral, glue, and bootstrap information."""

    def __init__(
        self,
        transport: DNSTransportProtocol,
        transport_config: TransportConfig | None = None,
        bootstrap: NameserverBootstrap | None = None,
    ) -> None:
        self.transport = transport
        self.transport_config = transport_config
        self.bootstrap = bootstrap

    def query(
        self,
        response: DNSMessage,
        domain_name: str,
        delegated_zone: str,
        transaction_id: int = 0x1234,
        record_type: str = "A",
    ) -> tuple[DNSMessage, TransportResult]:
        """Follow a referral and query one of its TLD nameservers."""

        nameservers = ReferralParser.select_nameservers(
            response,
            delegated_zone,
        )

        if not nameservers:
            raise ValueError(
                f"No nameservers found for delegated zone "
                f"'{delegated_zone}'."
            )

        glue = GlueExtractor.extract(
            response,
            nameservers,
        )

        servers: list[ServerAddress] = []

        for nameserver in nameservers:
            addresses = glue.get(nameserver, [])

            if not addresses and self.bootstrap is not None:
                addresses = self.bootstrap.resolve(nameserver)

            for address in addresses:
                servers.append(
                    ServerAddress(
                        ip=address,
                        port=53,
                        protocol="UDP",
                        name=nameserver.value,
                    )
                )

        if not servers:
            raise ValueError(
                "No nameserver addresses were available from glue "
                "or nameserver bootstrap."
            )

        message = DNSMessage(
            header=DNSHeader(
                transaction_id=transaction_id,
                rd=0,
            ),
            questions=[
                DNSQuestion(
                    qname=DNSName(domain_name),
                    qtype=record_type,
                    qclass="IN",
                )
            ],
        )

        query_bytes = DNSMessageEncoder.encode(message)

        result = self.transport.send_query_with_fallback(
            servers,
            query_bytes,
            self.transport_config,
        )

        decoded_response = DNSMessageDecoder.decode(
            result.raw_response
        )

        return decoded_response, result