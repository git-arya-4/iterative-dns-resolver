## Summary of Change
<!-- Provide a clear description of the changes introduced by this PR. -->

## Subsystem / Scope
<!-- Select the subsystem(s) affected by this PR: -->
- [ ] `foundation` (Scaffolding / Config / CI)
- [ ] `model` (Avidipta - DNS internal data model)
- [ ] `wire` (Avidipta - RFC 1035 wire codec & compression)
- [ ] `transport` (Shriyansh - UDP/TCP sockets, retry, timeout)
- [ ] `iterative` (Shriyansh - Root -> TLD -> Auth referral resolution)
- [ ] `cache` (Swastik - TTL eviction, RFC 2308 negative cache)
- [ ] `core` (Arya - CNAME processing & final resolver orchestration)
- [ ] `server` (Swastik / Arya / Avidipta - Local DNS server mode)
- [ ] `testing` (Unit / Integration / Malformed tests)
- [ ] `integration` (End-to-end resolver flow)
- [ ] `experiments` (Performance & trace analysis)
- [ ] `documentation` (Specs, architecture, guidelines)
- [ ] `stretch` (EDNS0, DNSSEC, DNS-over-TCP server)

## Breaking Changes / Contract Impact
- [ ] Contract changes introduced (`src/idns/contracts/`)
- [ ] Reviewed and approved by affected subsystem owners

## Checklist & Review Rules
- [ ] No direct pushes to `main` branch.
- [ ] Unit tests added/updated for affected subsystem under `tests/unit/`.
- [ ] Deterministic mocks / raw packet fixtures used for unit testing (no live Internet in unit tests).
- [ ] Resolver remains strictly independent of `dig +trace`.
- [ ] No prohibited external DNS libraries used (`dnspython`, `miekg/dns`, `dnsjava`, `getaddrinfo`).
- [ ] No hardcoded forwarding to `8.8.8.8` or secondary public resolvers.

## Test Evidence & Reviewer Acknowledgements
<!-- Paste the output of `pytest -v` or describe local verification performed. -->
```
pytest results here
```
