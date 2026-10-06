from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from idns.contracts.resolver import ResolutionContext
from idns.errors import DNSTimeoutError
from idns.iterative.engine import IterativeEngine
from idns.model import ARecord, DNSHeader, DNSMessage, DNSName, NSRecord


def make_response(
    *,
    rcode=0,
    answers=None,
    authorities=None,
    additionals=None,
):
    return DNSMessage(
        header=DNSHeader(transaction_id=0x1234, rcode=rcode),
        answers=answers or [],
        authorities=authorities or [],
        additionals=additionals or [],
    )


def make_engine():
    transport = MagicMock()
    root_servers = [{"ip": "198.41.0.4", "name": "a.root-servers.net"}]
    return IterativeEngine(transport, root_servers)


def test_resolve_returns_root_final_answer():
    engine = make_engine()

    response = make_response(
        answers=[
            ARecord(
                name=DNSName("example.com"),
                address="93.184.216.34",
                ttl=300,
            )
        ]
    )

    with patch("idns.iterative.engine.RootQuery") as root_query:
        root_query.return_value.query.return_value = (
            response,
            SimpleNamespace(rtt_ms=5.0),
        )

        result = engine.resolve("example.com", "A")

    assert result.domain_name == "example.com"
    assert result.record_type == "A"
    assert result.answers == response.answers
    assert result.query_count == 1
    assert result.total_rtt_ms == 5.0
    assert result.trace_log == ["root query: example.com A"]


def test_resolve_returns_root_response_for_single_label_domain():
    engine = make_engine()

    response = make_response()

    with patch("idns.iterative.engine.RootQuery") as root_query:
        root_query.return_value.query.return_value = (
            response,
            SimpleNamespace(rtt_ms=2.5),
        )

        result = engine.resolve("localhost", "A")

    assert result.domain_name == "localhost"
    assert result.answers == []
    assert result.query_count == 1
    assert result.total_rtt_ms == 2.5
    root_query.return_value.query.assert_called_once_with(
        "localhost",
        record_type="A",
    )


def test_resolve_returns_tld_final_answer():
    engine = make_engine()

    root_response = make_response()
    tld_response = make_response(
        answers=[
            ARecord(
                name=DNSName("example.com"),
                address="93.184.216.34",
                ttl=300,
            )
        ]
    )

    with (
        patch("idns.iterative.engine.RootQuery") as root_query,
        patch("idns.iterative.engine.TLDQuery") as tld_query,
    ):
        root_query.return_value.query.return_value = (
            root_response,
            SimpleNamespace(rtt_ms=2.0),
        )
        tld_query.return_value.query.return_value = (
            tld_response,
            SimpleNamespace(rtt_ms=3.0),
        )

        result = engine.resolve("example.com", "A")

    assert result.answers == tld_response.answers
    assert result.query_count == 2
    assert result.total_rtt_ms == 5.0
    assert result.trace_log == [
        "root query: example.com A",
        "tld query: example.com A",
    ]

    tld_query.return_value.query.assert_called_once_with(
        root_response,
        "example.com",
        "com",
        record_type="A",
    )


def test_resolve_returns_authoritative_final_answer_using_glue():
    engine = make_engine()

    root_response = make_response()
    tld_response = make_response(
        authorities=[
            NSRecord(
                name=DNSName("example.com"),
                nameserver=DNSName("ns1.example.com"),
                ttl=300,
            )
        ]
    )
    auth_response = make_response(
        answers=[
            ARecord(
                name=DNSName("example.com"),
                address="93.184.216.34",
                ttl=300,
            )
        ]
    )

    nameserver = DNSName("ns1.example.com")

    with (
        patch("idns.iterative.engine.RootQuery") as root_query,
        patch("idns.iterative.engine.TLDQuery") as tld_query,
        patch("idns.iterative.engine.ReferralParser.select_nameservers") as select_ns,
        patch("idns.iterative.engine.GlueExtractor.extract") as extract_glue,
        patch("idns.iterative.engine.AuthoritativeQuery") as auth_query,
    ):
        root_query.return_value.query.return_value = (
            root_response,
            SimpleNamespace(rtt_ms=1.0),
        )
        tld_query.return_value.query.return_value = (
            tld_response,
            SimpleNamespace(rtt_ms=2.0),
        )
        select_ns.return_value = [nameserver]
        extract_glue.return_value = {
            nameserver: ["192.0.2.53"],
        }
        auth_query.return_value.query.return_value = (
            auth_response,
            SimpleNamespace(rtt_ms=4.0),
        )

        result = engine.resolve("example.com", "A")

    assert result.answers == auth_response.answers
    assert result.query_count == 3
    assert result.total_rtt_ms == 7.0
    assert result.trace_log[-1] == (
        "authoritative query: ns1.example.com (192.0.2.53)"
    )
    assert result.queried_servers if hasattr(result, "queried_servers") else True

    auth_query.return_value.query.assert_called_once()
    server = auth_query.return_value.query.call_args.args[0]
    assert server.ip == "192.0.2.53"
    assert server.port == 53
    assert server.protocol == "UDP"
    assert server.name == "ns1.example.com"


def test_resolve_bootstraps_nameserver_when_glue_is_missing():
    engine = make_engine()

    root_response = make_response()
    tld_response = make_response(
        authorities=[
            NSRecord(
                name=DNSName("example.com"),
                nameserver=DNSName("ns1.example.com"),
                ttl=300,
            )
        ]
    )
    auth_response = make_response(
        answers=[
            ARecord(
                name=DNSName("example.com"),
                address="93.184.216.34",
                ttl=300,
            )
        ]
    )

    nameserver = DNSName("ns1.example.com")

    with (
        patch("idns.iterative.engine.RootQuery") as root_query,
        patch("idns.iterative.engine.TLDQuery") as tld_query,
        patch("idns.iterative.engine.ReferralParser.select_nameservers") as select_ns,
        patch("idns.iterative.engine.GlueExtractor.extract") as extract_glue,
        patch("idns.iterative.engine.AuthoritativeQuery") as auth_query,
    ):
        root_query.return_value.query.return_value = (
            root_response,
            SimpleNamespace(rtt_ms=1.0),
        )
        tld_query.return_value.query.return_value = (
            tld_response,
            SimpleNamespace(rtt_ms=2.0),
        )
        select_ns.return_value = [nameserver]
        extract_glue.return_value = {}

        engine.bootstrap.resolve = MagicMock(
            return_value=["192.0.2.53"]
        )

        auth_query.return_value.query.return_value = (
            auth_response,
            SimpleNamespace(rtt_ms=4.0),
        )

        result = engine.resolve("example.com", "A")

    engine.bootstrap.resolve.assert_called_once_with(nameserver)
    assert result.answers == auth_response.answers
    assert result.query_count == 3


def test_resolve_continues_to_next_referral():
    engine = make_engine()

    root_response = make_response()
    tld_response = make_response()
    first_referral = make_response(
        authorities=[
            NSRecord(
                name=DNSName("sub.example.com"),
                nameserver=DNSName("ns.sub.example.com"),
                ttl=300,
            )
        ]
    )
    final_response = make_response(
        answers=[
            ARecord(
                name=DNSName("www.sub.example.com"),
                address="192.0.2.80",
                ttl=300,
            )
        ]
    )

    ns1 = DNSName("ns.example.com")
    ns2 = DNSName("ns.sub.example.com")

    with (
        patch("idns.iterative.engine.RootQuery") as root_query,
        patch("idns.iterative.engine.TLDQuery") as tld_query,
        patch("idns.iterative.engine.ReferralParser.select_nameservers") as select_ns,
        patch("idns.iterative.engine.GlueExtractor.extract") as extract_glue,
        patch("idns.iterative.engine.AuthoritativeQuery") as auth_query,
    ):
        root_query.return_value.query.return_value = (
            root_response,
            SimpleNamespace(rtt_ms=1.0),
        )
        tld_query.return_value.query.return_value = (
            tld_response,
            SimpleNamespace(rtt_ms=2.0),
        )

        select_ns.side_effect = [
            [ns1],
            [ns2],
        ]

        extract_glue.side_effect = [
            {ns1: ["192.0.2.53"]},
            {ns2: ["192.0.2.54"]},
        ]

        auth_query.return_value.query.side_effect = [
            (
                first_referral,
                SimpleNamespace(rtt_ms=3.0),
            ),
            (
                final_response,
                SimpleNamespace(rtt_ms=4.0),
            ),
        ]

        result = engine.resolve("www.sub.example.com", "A")

    assert result.answers == final_response.answers
    assert result.query_count == 4
    assert result.total_rtt_ms == 10.0
    assert auth_query.return_value.query.call_count == 2


def test_resolve_raises_last_timeout_when_all_authoritative_servers_timeout():
    engine = make_engine()

    root_response = make_response()
    tld_response = make_response(
        authorities=[
            NSRecord(
                name=DNSName("example.com"),
                nameserver=DNSName("ns1.example.com"),
                ttl=300,
            )
        ]
    )

    nameserver = DNSName("ns1.example.com")
    timeout = DNSTimeoutError("192.0.2.53:53", 1.0)

    with (
        patch("idns.iterative.engine.RootQuery") as root_query,
        patch("idns.iterative.engine.TLDQuery") as tld_query,
        patch("idns.iterative.engine.ReferralParser.select_nameservers") as select_ns,
        patch("idns.iterative.engine.GlueExtractor.extract") as extract_glue,
        patch("idns.iterative.engine.AuthoritativeQuery") as auth_query,
    ):
        root_query.return_value.query.return_value = (
            root_response,
            SimpleNamespace(rtt_ms=1.0),
        )
        tld_query.return_value.query.return_value = (
            tld_response,
            SimpleNamespace(rtt_ms=2.0),
        )
        select_ns.return_value = [nameserver]
        extract_glue.return_value = {
            nameserver: ["192.0.2.53"],
        }
        auth_query.return_value.query.side_effect = timeout

        with pytest.raises(DNSTimeoutError):
            engine.resolve("example.com", "A")


def test_is_final_answer_detects_dns_error_rcodes():
    engine = make_engine()

    for rcode in (1, 2, 3, 4, 5):
        response = make_response(rcode=rcode)
        assert engine._is_final_answer(response, "example.com") is True


def test_is_final_answer_detects_nodata_with_soa():
    engine = make_engine()

    soa = SimpleNamespace(record_type="SOA")
    response = make_response(
        rcode=0,
        authorities=[soa],
    )

    assert engine._is_final_answer(response, "example.com") is True


def test_is_final_answer_rejects_empty_non_authoritative_response():
    engine = make_engine()

    response = make_response(rcode=0)

    assert engine._is_final_answer(response, "example.com") is False


def test_build_result_copies_context_and_response_data():
    engine = make_engine()

    response = make_response(
        rcode=3,
        answers=[],
        authorities=["authority"],
        additionals=["additional"],
    )
    context = ResolutionContext(
        query_count=3,
        cname_chain=["alias.example.com"],
        trace_log=["step 1"],
    )

    result = engine._build_result(
        "example.com",
        "A",
        response,
        context,
        12.5,
    )

    assert result.domain_name == "example.com"
    assert result.record_type == "A"
    assert result.answers == []
    assert result.authoritative_servers == ["authority"]
    assert result.additional_records == ["additional"]
    assert result.rcode == 3
    assert result.is_nxdomain is True
    assert result.is_cache_hit is False
    assert result.query_count == 3
    assert result.total_rtt_ms == 12.5
    assert result.cname_chain == ["alias.example.com"]
    assert result.trace_log == ["step 1"]
