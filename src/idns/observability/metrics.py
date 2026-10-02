from dataclasses import dataclass
from threading import Lock


@dataclass
class DNSMetrics:
    requests: int = 0
    successes: int = 0
    failures: int = 0
    malformed_requests: int = 0
    total_latency_ms: float = 0.0

    def record(self, *, success: bool, latency_ms: float, malformed: bool = False) -> None:
        self.requests += 1
        self.total_latency_ms += latency_ms
        if malformed:
            self.malformed_requests += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1

    @property
    def average_latency_ms(self) -> float:
        return self.total_latency_ms / self.requests if self.requests else 0.0


class ThreadSafeDNSMetrics(DNSMetrics):
    def __init__(self) -> None:
        super().__init__()
        self._lock = Lock()

    def record(self, **kwargs) -> None:
        with self._lock:
            super().record(**kwargs)

    @property
    def average_latency_ms(self) -> float:
        with self._lock:
            return super().average_latency_ms
