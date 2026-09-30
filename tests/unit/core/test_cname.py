"""Tests for CNAME processing and safety."""

import pytest
from idns.core.cname import CNAMEChainProcessor
from idns.contracts.resolver import ResolutionContext, ResolverResult
from idns.model import CNAMERecord, ARecord, DNSName
from idns.errors import CNAMELoopError, MaxDepthExceededError


def mock_resolver(domain: str, record_type: str, context: ResolutionContext) -> ResolverResult:
    # A simple mock resolver that returns A records or CNAMEs based on the domain
    if domain == "alias.example":
        return ResolverResult(domain, record_type, answers=[CNAMERecord(DNSName("alias.example"), DNSName("target.example"), 300)])
    if domain == "target.example":
        return ResolverResult(domain, record_type, answers=[ARecord(DNSName("target.example"), "1.2.3.4", 300)])
    if domain == "loop1":
        return ResolverResult(domain, record_type, answers=[CNAMERecord(DNSName("loop1"), DNSName("loop2"), 300)])
    if domain == "loop2":
        return ResolverResult(domain, record_type, answers=[CNAMERecord(DNSName("loop2"), DNSName("loop1"), 300)])
    if domain.startswith("depth"):
        num = int(domain[5:])
        return ResolverResult(domain, record_type, answers=[CNAMERecord(DNSName(domain), DNSName(f"depth{num+1}"), 300)])
    
    return ResolverResult(domain, record_type, answers=[], is_nxdomain=True, rcode=3)


def test_cname_processing_follows_chain():
    processor = CNAMEChainProcessor(mock_resolver)
    ctx = ResolutionContext()
    
    # Simulate an initial query to alias.example that returned the CNAME
    initial = ResolverResult("alias.example", "A", answers=[CNAMERecord(DNSName("alias.example"), DNSName("target.example"), 300)])
    
    final = processor.process("alias.example", "A", initial, ctx)
    assert len(final.answers) == 2
    assert isinstance(final.answers[0], CNAMERecord)
    assert isinstance(final.answers[1], ARecord)
    assert final.answers[1].address == "1.2.3.4"
    assert "alias.example" in ctx.cname_chain
    assert ctx.current_depth == 1


def test_explicit_cname_query_not_followed():
    processor = CNAMEChainProcessor(mock_resolver)
    ctx = ResolutionContext()
    
    initial = ResolverResult("alias.example", "CNAME", answers=[CNAMERecord(DNSName("alias.example"), DNSName("target.example"), 300)])
    final = processor.process("alias.example", "CNAME", initial, ctx)
    assert len(final.answers) == 1
    assert ctx.current_depth == 0  # Did not follow


def test_cname_loop_detection():
    processor = CNAMEChainProcessor(mock_resolver)
    ctx = ResolutionContext()
    
    initial = ResolverResult("loop1", "A", answers=[CNAMERecord(DNSName("loop1"), DNSName("loop2"), 300)])
    with pytest.raises(CNAMELoopError):
        processor.process("loop1", "A", initial, ctx)


def test_cname_depth_exceeded():
    processor = CNAMEChainProcessor(mock_resolver)
    ctx = ResolutionContext(max_depth=3)
    
    initial = ResolverResult("depth1", "A", answers=[CNAMERecord(DNSName("depth1"), DNSName("depth2"), 300)])
    with pytest.raises(MaxDepthExceededError):
        processor.process("depth1", "A", initial, ctx)


def test_cname_intra_response_increments_depth():
    # Defect fix verification: Even if the CNAME is in the same response, depth must increment
    processor = CNAMEChainProcessor(mock_resolver)
    ctx = ResolutionContext()
    
    initial = ResolverResult("a.example", "A", answers=[
        CNAMERecord(DNSName("a.example"), DNSName("b.example"), 300),
        CNAMERecord(DNSName("b.example"), DNSName("c.example"), 300),
        ARecord(DNSName("c.example"), "1.1.1.1", 300),
    ])
    
    final = processor.process("a.example", "A", initial, ctx)
    assert len(final.answers) == 3
    assert ctx.current_depth == 2  # Two transitions: a->b, b->c
    assert "a.example" in ctx.cname_chain
    assert "b.example" in ctx.cname_chain
