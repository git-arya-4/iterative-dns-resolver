import time

from idns.contracts.resolver import ResolutionContext
from idns.observability.metrics import DNSMetrics
from idns.wire import DNSMessageDecoder, DNSMessageEncoder
from idns.server.response import DNSResponseBuilder


class DNSRequestHandler:
    def __init__(self, resolver, metrics: DNSMetrics | None = None):
        self.resolver = resolver
        self.metrics = metrics or DNSMetrics()

    def handle(self, packet: bytes, client_address=None) -> tuple[bytes, tuple | None]:
        started = time.perf_counter()
        request = None
        try:
            request = DNSMessageDecoder.decode(packet)
            if request.header.qr or len(request.questions) != 1:
                response = DNSResponseBuilder.error(request, 1)
                self.metrics.record(success=False, malformed=True, latency_ms=self._elapsed(started))
                return DNSMessageEncoder.encode(response), client_address
            question = request.questions[0]
            result = self.resolver.resolve(str(question.qname), question.qtype, ResolutionContext())
            response = DNSResponseBuilder.build(request, result)
            self.metrics.record(success=True, latency_ms=self._elapsed(started))
        except Exception:
            if request is None:
                transaction_id = int.from_bytes(packet[:2].ljust(2, b"\0"), "big")
                response = DNSResponseBuilder.error(transaction_id, 1)
                self.metrics.record(success=False, malformed=True, latency_ms=self._elapsed(started))
            else:
                response = DNSResponseBuilder.error(request, 2)
                self.metrics.record(success=False, latency_ms=self._elapsed(started))
        return DNSMessageEncoder.encode(response), client_address

    @staticmethod
    def _elapsed(started: float) -> float:
        return (time.perf_counter() - started) * 1000
