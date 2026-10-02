from dataclasses import dataclass

from idns.cli import build_parser, main
from idns.contracts.resolver import ResolverResult
from idns.model import ARecord, DNSName


@dataclass
class FakeResolver:
    result: ResolverResult
    calls: list[tuple[str, str]]

    def resolve(self, domain_name, record_type, context=None):
        self.calls.append((domain_name, record_type))
        context.trace_log.append("fake resolution event")
        self.result.trace_log = list(context.trace_log)
        return self.result


def test_resolve_command_invokes_real_resolver_and_prints_result(monkeypatch, capsys, tmp_path):
    hints = tmp_path / "root_hints.json"
    hints.write_text('{"root_servers": [{"name": "root", "ipv4": "198.41.0.4"}]}')
    fake = FakeResolver(
        ResolverResult(
            "example.com",
            "A",
            answers=[ARecord(DNSName("example.com"), "1.2.3.4", 300)],
        ),
        [],
    )
    monkeypatch.setattr("idns.cli.CoreResolver", lambda **_: fake)

    assert main(["--config", str(hints), "resolve", "example.com", "a", "--trace"]) == 0
    output = capsys.readouterr().out
    assert fake.calls == [("example.com", "A")]
    assert "Query: example.com A" in output
    assert "example.com 300 IN A 1.2.3.4" in output
    assert "fake resolution event" in output


def test_cli_server_starts_without_entering_real_loop(monkeypatch, capsys):
    started = []

    class FakeServer:
        def __init__(self, resolver, host, port):
            started.append((resolver, host, port))

        def serve_forever(self):
            return

    monkeypatch.setattr("idns.cli.UDPDNSServer", FakeServer)
    assert main(["server"]) == 0
    assert started[0][1:] == ("127.0.0.1", 5353)


def test_cli_experiment_reports_unimplemented(capsys):
    assert main(["experiment", "cold_warm"]) == 2
    assert "not yet implemented" in capsys.readouterr().err


def test_resolve_parser_accepts_positional_case_insensitive_type():
    args = build_parser().parse_args(["resolve", "example.com", "aaaa"])
    assert args.record_type == "AAAA"
    assert args.type_option is None
