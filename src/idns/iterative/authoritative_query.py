"""Authoritative nameserver query support."""

from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.model import DNSHeader, DNSMessage, DNSName, DNSQuestion
from idns.wire.message_decoder import DNSMessageDecoder
from idns.wire.message_encoder import DNSMessageEncoder


class AuthoritativeQuery:
    """Query an authoritative DNS nameserver."""

    def __init__(
        self,
        transport: DNSTransportProtocol,
        transport_config: TransportConfig | None = None,
    ) -> None:
        self.transport = transport
        self.transport_config = transport_config

    def query(
        self,
        server: ServerAddress,
        domain_name: str,
        record_type: str = "A",
        transaction_id: int = 0x1234,
    ) -> tuple[DNSMessage, TransportResult]:
        """Query the authoritative nameserver."""

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

        result = self.transport.send_query(
            server,
            query_bytes,
            self.transport_config,
        )

        response = DNSMessageDecoder.decode(result.raw_response)

        return response, result