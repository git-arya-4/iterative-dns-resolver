"""
DNS Socket Transport Subsystem.

Owner: Shriyansh
Phase: Phase 2 & 3
Responsibilities:
- Socket-level UDP query transmission and response parsing
- Timeout, retry, and candidate server selection algorithms
- TCP fallback when DNS response TC (Truncation) bit is set
- Implementation of DNSTransportProtocol contract
"""
