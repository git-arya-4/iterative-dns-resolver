"""Root-server query support for iterative DNS resolution."""

from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.model import (
    DNSHeader,
    DNSMessage,
    DNSName,
    DNSQuestion,
)
from idns.wire.message_decoder import DNSMessageDecoder
from idns.wire.message_encoder import DNSMessageEncoder


class RootQuery:
    """Send DNS queries to the configured root servers."""

    def __init__(
        self,
        root_servers: list[dict[str, str]],
        transport: DNSTransportProtocol,
        transport_config: TransportConfig | None = None,
    ) -> None:
        self.root_servers = root_servers
        self.transport = transport
        self.transport_config = transport_config

    def query(
        self,
        domain_name: str,
        record_type: str = "A",
        transaction_id: int = 0x1234,
    ) -> tuple[DNSMessage, TransportResult]:
        """Query the root-server candidates for a domain."""

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

        servers = [
            ServerAddress(
                ip=root["ipv4"],
                port=53,
                protocol="UDP",
                name=root.get("name"),
            )
            for root in self.root_servers
            if root.get("ipv4")
        ]

        result = self.transport.send_query_with_fallback(
            servers,
            query_bytes,
            self.transport_config,
        )

        response = DNSMessageDecoder.decode(result.raw_response)

        return response, result