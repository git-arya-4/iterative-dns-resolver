import json

import pytest

from idns.contracts.resolver import ResolverResult
from idns.experiments import load_trace, run_cache_hit_ratio


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, domain, record_type):
        self.calls.append((domain, record_type))
        return ResolverResult(domain, record_type, is_cache_hit=len(self.calls) > 1)


def test_replayed_trace_reports_hits_and_misses():
    resolver = FakeResolver()
    trace = [
        {"domain": "example.com", "record_type": "a"},
        {"domain": "example.com", "record_type": "a"},
        {"domain": "iana.org"},
    ]

    result = run_cache_hit_ratio(resolver, trace)

    assert result["total_queries"] == 3
    assert result["cache_hits"] == 2
    assert result["cache_misses"] == 1
    assert result["hit_ratio"] == pytest.approx(2 / 3)
    assert resolver.calls == [("example.com", "A"), ("example.com", "A"), ("iana.org", "A")]


def test_load_trace_validates_json_file(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps([{"domain": "Example.COM", "record_type": "a"}]), encoding="utf-8")

    assert load_trace(path) == [{"domain": "Example.COM", "record_type": "A"}]


def test_load_trace_rejects_non_array(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps({"domain": "example.com"}), encoding="utf-8")

    with pytest.raises(ValueError, match="JSON array"):
        load_trace(path)
