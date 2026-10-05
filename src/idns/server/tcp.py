import socket
import threading

from idns.server.handler import DNSRequestHandler


class TCPDNSServer:
    """Serve DNS queries over DNS-over-TCP framing."""

    def __init__(self, resolver, host="127.0.0.1", port=5353, metrics=None):
        self.host, self.port = host, port
        self.handler = DNSRequestHandler(resolver, metrics)
        self._socket = None
        self._stop_event = threading.Event()
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self._socket = sock
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.2)
            sock.bind((self.host, self.port))
            sock.listen()
            self.port = sock.getsockname()[1]
            while not self._stop_event.is_set():
                try:
                    connection, _ = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
                if self._register_connection(connection):
                    threading.Thread(
                        target=self._serve_connection,
                        args=(connection,),
                        daemon=True,
                    ).start()
            self._socket = None

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            self.handle_connection(connection)
        finally:
            with self._connections_lock:
                self._connections.discard(connection)

    def _register_connection(self, connection: socket.socket) -> bool:
        """Register an accepted connection unless shutdown has begun."""
        with self._connections_lock:
            if self._stop_event.is_set():
                connection.close()
                return False
            self._connections.add(connection)
            return True

    def handle_connection(self, connection: socket.socket) -> None:
        try:
            length_bytes = self._receive_exact(connection, 2)
            length = int.from_bytes(length_bytes, "big")
            if length == 0:
                return
            packet = self._receive_exact(connection, length)
            response, _ = self.handler.handle(packet)
            if len(response) > 65535:
                return
            connection.sendall(len(response).to_bytes(2, "big") + response)
        except (ConnectionError, OSError):
            return
        finally:
            connection.close()

    def close(self) -> None:
        self._stop_event.set()
        if self._socket:
            self._socket.close()
        with self._connections_lock:
            connections = tuple(self._connections)
        for connection in connections:
            connection.close()

    @staticmethod
    def _receive_exact(connection: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise ConnectionError("TCP client closed before full DNS message")
            data.extend(chunk)
        return bytes(data)
