"""UDP transport implementation for DNS queries."""

import socket
import time

from idns.contracts.transport import (
    DNSTransportProtocol,
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.errors import (
    DNSTimeoutError,
    ServerUnreachableError,
    TransportError,
)
from idns.wire import DNSHeaderCodec
from idns.wire.cursor import ByteCursor


class UDPTransport(DNSTransportProtocol):
    """Send DNS queries over UDP."""

    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config: TransportConfig | None = None,
    ) -> TransportResult:
        """Send a DNS query and return the matching raw response."""

        if config is None:
            config = TransportConfig()

        expected_transaction_id = self._get_transaction_id(query_bytes)
        last_error: Exception | None = None

        # max_retries means retries after the initial attempt.
        total_attempts = 1 + config.max_retries

        for _ in range(total_attempts):
            start_time = time.perf_counter()

            try:
                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                ) as sock:
                    sock.settimeout(config.timeout_seconds)

                    sock.sendto(
                        query_bytes,
                        (server.ip, server.port),
                    )

                    raw_response, source_address = sock.recvfrom(
                        config.buffer_size
                    )

                    source_ip, source_port = source_address

                    if (
                        source_ip != server.ip
                        or source_port != server.port
                    ):
                        raise ServerUnreachableError(
                            f"DNS response received from unexpected server "
                            f"'{source_ip}:{source_port}', expected "
                            f"'{server.ip}:{server.port}'."
                        )

                    response_header = DNSHeaderCodec.decode(
                        ByteCursor(raw_response)
                    )

                    if (
                        response_header.transaction_id
                        != expected_transaction_id
                    ):
                        raise TransportError(
                            "DNS response transaction ID does not match "
                            "the query transaction ID."
                        )

                    if response_header.qr != 1:
                        raise TransportError(
                            "DNS response does not have the response flag set."
                        )

                rtt_ms = (time.perf_counter() - start_time) * 1000

                return TransportResult(
                    raw_response=raw_response,
                    server_used=server,
                    rtt_ms=rtt_ms,
                    tc_bit_set=bool(response_header.tc),
                )

            except socket.timeout as exc:
                last_error = exc

            except OSError as exc:
                raise ServerUnreachableError(
                    f"DNS server '{server.ip}:{server.port}' "
                    f"is unreachable: {exc}"
                ) from exc

        raise DNSTimeoutError(
            server=f"{server.ip}:{server.port}",
            timeout=config.timeout_seconds,
        ) from last_error

    @staticmethod
    def _get_transaction_id(query_bytes: bytes) -> int:
        """Extract the transaction ID from a DNS query."""

        try:
            header = DNSHeaderCodec.decode(
                ByteCursor(query_bytes)
            )
        except Exception as exc:
            raise TransportError(
                "Unable to decode DNS query header."
            ) from exc

        return header.transaction_id