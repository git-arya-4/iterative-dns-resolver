from idns.contracts.resolver import ResolverResult
from idns.model import DNSHeader, DNSMessage, DNSName, DNSQuestion
from idns.server import DNSRequestHandler, DNSResponseBuilder
from idns.observability import DNSMetrics
from idns.wire import DNSMessageEncoder
from idns.wire.message_decoder import DNSMessageDecoder


class FakeResolver:
    def resolve(self, domain_name, record_type="A", context=None):
        return ResolverResult(domain_name, record_type)


def query_packet():
    return DNSMessageEncoder.encode(
        DNSMessage(
            header=DNSHeader(transaction_id=0x1234, rd=1),
            questions=[DNSQuestion(DNSName("example.com"), "A")],
        )
    )


def test_response_builder_preserves_query_and_sets_response_flags():
    request = DNSMessage(
        header=DNSHeader(transaction_id=7, rd=1),
        questions=[DNSQuestion(DNSName("example.com"), "A")],
    )
    response = DNSResponseBuilder.build(request, ResolverResult("example.com", "A"))
    assert response.header.transaction_id == 7
    assert response.header.qr == 1
    assert response.header.rd == 1
    assert response.header.ra == 1
    assert response.questions == request.questions


def test_handler_resolves_query_and_returns_wire_response():
    metrics = DNSMetrics()
    handler = DNSRequestHandler(FakeResolver(), metrics=metrics)
    response = DNSMessageDecoder.decode(handler.handle(query_packet(), ("127.0.0.1", 40000))[0])
    assert response.header.transaction_id == 0x1234
    assert response.header.qr == 1
    assert response.header.rcode == 0
    assert metrics.requests == 1
    assert metrics.successes == 1


def test_handler_returns_formerr_for_malformed_packet():
    handler = DNSRequestHandler(FakeResolver())
    response = DNSMessageDecoder.decode(handler.handle(b"bad", ("127.0.0.1", 1))[0])
    assert response.header.qr == 1
    assert response.header.rcode == 1
