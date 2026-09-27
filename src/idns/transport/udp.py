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

                    # Keep receiving until the response matches this query.
                    # An unrelated UDP packet must not terminate the query.
                    while True:
                        raw_response, source_address = sock.recvfrom(
                            config.buffer_size
                        )

                        source_ip, source_port = source_address

                        if (
                            source_ip != server.ip
                            or source_port != server.port
                        ):
                            raise ServerUnreachableError(
                                f"DNS response received from unexpected "
                                f"server '{source_ip}:{source_port}', "
                                f"expected '{server.ip}:{server.port}'."
                            )

                        if len(raw_response) < 4:
                            raise TransportError(
                                "DNS response is too short to contain "
                                "a DNS header."
                            )

                        response_transaction_id = int.from_bytes(
                            raw_response[0:2],
                            "big",
                        )

                        if response_transaction_id != expected_transaction_id:
                            continue

                        flags = int.from_bytes(
                            raw_response[2:4],
                            "big",
                        )

                        qr = bool(flags & 0x8000)

                        if not qr:
                            raise TransportError(
                                "DNS response does not have the response "
                                "flag set."
                            )

                        tc_bit_set = bool(flags & 0x0200)
                        break

                rtt_ms = (time.perf_counter() - start_time) * 1000

                return TransportResult(
                    raw_response=raw_response,
                    server_used=server,
                    rtt_ms=rtt_ms,
                    tc_bit_set=tc_bit_set,
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

    def send_query_with_fallback(
        self,
        servers: list[ServerAddress],
        query_bytes: bytes,
        config: TransportConfig | None = None,
    ) -> TransportResult:
        """Try candidate DNS servers using the configured retry policy."""

        if not servers:
            raise ServerUnreachableError(
                "No candidate DNS servers were provided."
            )

        last_error: Exception | None = None

        for server in servers:
            try:
                return self.send_query(
                    server,
                    query_bytes,
                    config,
                )
            except (DNSTimeoutError, ServerUnreachableError) as exc:
                last_error = exc

        raise ServerUnreachableError(
            "All candidate DNS servers failed."
        ) from last_error

    @staticmethod
    def _get_transaction_id(query_bytes: bytes) -> int:
        """Extract the transaction ID from a DNS query."""

        if len(query_bytes) < 2:
            raise TransportError(
                "DNS query is too short to contain a transaction ID."
            )

        return int.from_bytes(query_bytes[0:2], "big")