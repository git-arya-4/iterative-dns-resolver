import socket

from idns.server.handler import DNSRequestHandler


class UDPDNSServer:
    def __init__(self, resolver, host="127.0.0.1", port=5353, metrics=None):
        self.host, self.port = host, port
        self.handler = DNSRequestHandler(resolver, metrics)
        self._socket = None

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            self._socket = sock
            sock.bind((self.host, self.port))
            self.port = sock.getsockname()[1]
            while True:
                packet, address = sock.recvfrom(4096)
                response, _ = self.handler.handle(packet, address)
                sock.sendto(response, address)

    def close(self) -> None:
        if self._socket:
            self._socket.close()
