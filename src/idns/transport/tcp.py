"""TCP transport implementation for DNS queries."""

import socket
import time

from idns.contracts.transport import (
    ServerAddress,
    TransportConfig,
    TransportResult,
)
from idns.errors import (
    DNSTimeoutError,
    ServerUnreachableError,
    TransportError,
)


class TCPTransport:
    """Send DNS queries over TCP."""

    def send_query(
        self,
        server: ServerAddress,
        query_bytes: bytes,
        config: TransportConfig | None = None,
    ) -> TransportResult:
        """Send a DNS query over TCP and return the raw response."""

        if config is None:
            config = TransportConfig()

        if len(query_bytes) > 65535:
            raise TransportError(
                "DNS query is too large for the TCP length prefix."
            )

        expected_transaction_id = self._get_transaction_id(query_bytes)

        start_time = time.perf_counter()

        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            ) as sock:
                sock.settimeout(config.timeout_seconds)
                sock.connect((server.ip, server.port))

                # DNS over TCP prefixes every message with a 2-byte
                # network-order message length.
                length_prefix = len(query_bytes).to_bytes(2, "big")

                sock.sendall(length_prefix + query_bytes)

                response_length_bytes = self._receive_exact(
                    sock,
                    2,
                )

                response_length = int.from_bytes(
                    response_length_bytes,
                    "big",
                )

                if response_length < 12:
                    raise TransportError(
                        "DNS response is too short to contain "
                        "a DNS header."
                    )

                raw_response = self._receive_exact(
                    sock,
                    response_length,
                )

        except socket.timeout as exc:
            raise DNSTimeoutError(
                server=f"{server.ip}:{server.port}",
                timeout=config.timeout_seconds,
            ) from exc

        except OSError as exc:
            raise ServerUnreachableError(
                f"DNS server '{server.ip}:{server.port}' "
                f"is unreachable: {exc}"
            ) from exc

        response_transaction_id = int.from_bytes(
            raw_response[0:2],
            "big",
        )

        if response_transaction_id != expected_transaction_id:
            raise TransportError(
                "DNS response transaction ID does not match "
                "the query transaction ID."
            )

        flags = int.from_bytes(
            raw_response[2:4],
            "big",
        )

        if not (flags & 0x8000):
            raise TransportError(
                "DNS response does not have the response flag set."
            )

        rtt_ms = (time.perf_counter() - start_time) * 1000

        return TransportResult(
            raw_response=raw_response,
            server_used=server,
            rtt_ms=rtt_ms,
            tc_bit_set=bool(flags & 0x0200),
            is_tcp=True,
        )

    @staticmethod
    def _receive_exact(
        sock: socket.socket,
        size: int,
    ) -> bytes:
        """Receive exactly the requested number of bytes."""

        data = bytearray()

        while len(data) < size:
            chunk = sock.recv(size - len(data))

            if not chunk:
                raise ServerUnreachableError(
                    "DNS server closed the TCP connection before "
                    "the complete response was received."
                )

            data.extend(chunk)

        return bytes(data)

    @staticmethod
    def _get_transaction_id(query_bytes: bytes) -> int:
        """Extract the transaction ID from a DNS query."""

        if len(query_bytes) < 2:
            raise TransportError(
                "DNS query is too short to contain a transaction ID."
            )

        return int.from_bytes(query_bytes[0:2], "big")