from types import SimpleNamespace

from idns.experiments import count_dig_trace_responses, run_query_count_comparison


class FakeResolver:
    def resolve(self, domain, record_type):
        return SimpleNamespace(query_count=4)


def test_count_dig_trace_responses_counts_received_lines():
    output = """;; Received 80 bytes from 198.41.0.4#53
;; Received 100 bytes from 192.0.2.1#53
;; Received 120 bytes from 192.0.2.2#53
"""

    assert count_dig_trace_responses(output) == 3


def test_query_count_comparison_reports_difference():
    def fake_runner(*args, **kwargs):
        return SimpleNamespace(
            stdout=";; Received 100 bytes from 192.0.2.1#53\n"
            ";; Received 100 bytes from 192.0.2.2#53\n",
            stderr="",
            returncode=0,
        )

    result = run_query_count_comparison(FakeResolver(), "example.com", runner=fake_runner)

    assert result["resolver_query_count"] == 4
    assert result["dig_trace_query_count"] == 2
    assert result["difference"] == 2
    assert result["dig_available"] is True


def test_query_count_comparison_reports_missing_dig():
    def missing_runner(*args, **kwargs):
        raise FileNotFoundError("dig not found")

    result = run_query_count_comparison(FakeResolver(), "example.com", runner=missing_runner)

    assert result["resolver_query_count"] == 4
    assert result["dig_trace_query_count"] is None
    assert result["difference"] is None
    assert result["dig_available"] is False
