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
)


class UDPTransport(DNSTransportProtocol):
    """Send DNS queries over UDP."""

    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config: TransportConfig | None = None,
    ) -> TransportResult:
        """Send a DNS query and return the raw response."""

        if config is None:
            config = TransportConfig()

        last_error: Exception | None = None

        for _ in range(config.max_retries):
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

                    raw_response, _ = sock.recvfrom(
                        config.buffer_size
                    )

                rtt_ms = (time.perf_counter() - start_time) * 1000

                return TransportResult(
                    raw_response=raw_response,
                    server_used=server,
                    rtt_ms=rtt_ms,
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