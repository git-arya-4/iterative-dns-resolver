# Iterative DNS Resolution Engine Specification

**Owner**: Shriyansh  
**Subsystem Package**: `src/idns/transport/` and `src/idns/iterative/`  
**Phase**: Phase 2, 3, & 4  

# Iterative resolution

The resolver follows referrals from the configured root hints through the
appropriate TLD and authoritative nameservers. In-bailiwick A/AAAA glue is
used directly; nameservers without usable glue are bootstrapped iteratively.

Every successful DNS exchange, including the A and AAAA queries made while
bootstrapping a nameserver, increments `ResolverResult.query_count`. A timeout
or network-unreachable authoritative candidate is recorded in the trace and
the next candidate is tried before the error is returned.

Authoritative `NOERROR` responses with no answer records are classified as
NODATA only when they contain an SOA authority record. Empty referrals are not
negative answers and are not inserted into the negative cache.

UDP responses with `TC=1` are retried over TCP by the transport layer.
