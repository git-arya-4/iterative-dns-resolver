from types import SimpleNamespace

from idns.experiments import run_unreachable_authoritative


def test_unreachable_experiment_records_resolver_failure():
    class FailingResolver:
        def resolve(self, domain, record_type):
            raise TimeoutError("authoritative server timed out")

    result = run_unreachable_authoritative(FailingResolver(), "example.com")

    assert result["completed"] is False
    assert result["expected_failure"] is True
    assert result["error_type"] == "TimeoutError"
    assert result["error"] == "authoritative server timed out"


def test_unreachable_experiment_reports_unexpected_success():
    class SuccessfulResolver:
        def resolve(self, domain, record_type):
            return SimpleNamespace(query_count=2, rcode=0, is_cache_hit=False)

    result = run_unreachable_authoritative(SuccessfulResolver(), "example.com", "a")

    assert result["completed"] is True
    assert result["expected_failure"] is False
    assert result["record_type"] == "A"
    assert result["query_count"] == 2
