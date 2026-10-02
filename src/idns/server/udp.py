import socket
import threading

from idns.server.handler import DNSRequestHandler


class UDPDNSServer:
    def __init__(self, resolver, host="127.0.0.1", port=5353, metrics=None):
        self.host, self.port = host, port
        self.handler = DNSRequestHandler(resolver, metrics)
        self._socket = None
        self._stop_event = threading.Event()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            self._socket = sock
            sock.settimeout(0.2)
            sock.bind((self.host, self.port))
            self.port = sock.getsockname()[1]
            while not self._stop_event.is_set():
                try:
                    packet, address = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
                response, _ = self.handler.handle(packet, address)
                try:
                    sock.sendto(response, address)
                except OSError:
                    if not self._stop_event.is_set():
                        raise
            self._socket = None

    def close(self) -> None:
        self._stop_event.set()
        if self._socket:
            self._socket.close()
