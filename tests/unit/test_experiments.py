from idns.contracts.resolver import ResolverResult
from idns.experiments import run_cold_warm


class FakeCache:
    def __init__(self):
        self.clear_calls = 0

    def clear(self):
        self.clear_calls += 1


class FakeResolver:
    def __init__(self):
        self.cache = FakeCache()
        self.calls = []

    def resolve(self, domain, record_type):
        self.calls.append((domain, record_type))
        return ResolverResult(domain, record_type)


def test_cold_warm_experiment_clears_before_cold_and_primes_warm_cache():
    resolver = FakeResolver()

    result = run_cold_warm(resolver, "example.com", "a", samples=3)

    assert result["record_type"] == "A"
    assert result["cold"]["summary"]["samples"] == 3
    assert result["warm"]["summary"]["samples"] == 3
    assert len(result["cold"]["latencies_ms"]) == 3
    assert len(result["warm"]["latencies_ms"]) == 3
    assert resolver.cache.clear_calls == 4
    assert len(resolver.calls) == 7


def test_cold_warm_experiment_rejects_invalid_sample_count():
    resolver = FakeResolver()

    try:
        run_cold_warm(resolver, "example.com", samples=0)
    except ValueError as error:
        assert str(error) == "samples must be at least 1"
    else:
        raise AssertionError("expected ValueError")
