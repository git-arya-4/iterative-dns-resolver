# Team Contribution & Development Guidelines

Welcome to the **Iterative DNS Resolver with Caching** repository. All team members (Arya, Avidipta, Shriyansh, Swastik) must adhere to these development rules and subsystem boundaries.

---

## 1. Core Development Rules

1. **No Direct Pushes to `main`**: All code contributions must be submitted via feature branches (`feature/<owner>-<topic>`) and merged via GitHub Pull Requests.
2. **Feature Branch Workflow**: Maintain clean git history with descriptive, attributable commit messages.
3. **Subsystem Test Ownership**: Every subsystem owner maintains unit and integration tests for their respective module.
4. **Contract Review Requirement**: Any change to shared contracts (`src/idns/contracts/`) or common errors (`src/idns/errors.py`) requires explicit review and approval from affected team members.
5. **Role of `dig +trace`**: `dig +trace` is strictly an experimental benchmark comparison tool.
6. **Independence**: The DNS resolver MUST NOT depend on or execute `dig +trace` as part of its resolution logic.
7. **Stretch Feature Isolation**: Stretch features (`src/idns/extensions/` - EDNS0, DNSSEC) must remain strictly isolated from mandatory P2 features.
8. **Integration Triage Protocol**: When component integration fails, classify the failure into one of the following subsystem layers before modifying code:
   - `model` (Avidipta)
   - `wire` (Avidipta)
   - `transport` (Shriyansh)
   - `iterative` (Shriyansh)
   - `cache` (Swastik)
   - `core` (Arya)
   - `server` (Swastik/Arya/Avidipta)
9. **Deterministic Unit Testing**: Unit tests must rely exclusively on deterministic mocks and binary packet fixtures (`tests/fixtures/`).
10. **Live Internet Scoping**: Live Internet queries are reserved strictly for system validation and performance experiment executions.

---

## 2. GitHub Issue Label Scheme

| Label Name | Description / Scope | Subsystem Owner |
|---|---|---|
| `foundation` | Repository skeleton, CI, config, contracts | Arya |
| `model` | Internal DNS data structures (Header, Question, RR, RDATA) | Avidipta |
| `wire` | Hand-crafted RFC 1035 wire codec & compression | Avidipta |
| `transport` | Socket UDP/TCP transport, retries, timeout, server selection | Shriyansh |
| `iterative` | Root -> TLD -> Auth referral traversal & glue resolution | Shriyansh |
| `cache` | TTL eviction engine & RFC 2308 negative caching | Swastik |
| `core` | Resolver orchestrator & CNAME loop/depth controls | Arya |
| `server` | Local DNS server daemon port listener | Swastik / Arya |
| `testing` | Unit, integration, system, and fixture test suites | All / Arya Coord |
| `integration` | End-to-end component integration | All / Arya Coord |
| `experiments` | Required experimental benchmark scripts & reports | All / Swastik Coord |
| `documentation` | Architecture docs, wire specs, guidelines | All |
| `bug` | Defect fixes and issue reports | All |
| `stretch` | EDNS(0), DNSSEC, DNS-over-TCP server mode | All |

---

## 3. Subsystem Ownership Summary

- **Arya**: Contracts (`src/idns/contracts/`), Core (`src/idns/core/`), CLI (`src/idns/cli.py`), Errors (`src/idns/errors.py`), Config (`config/`), CI (`.github/`), Testing/Integration Coordination.
- **Avidipta**: Data Model (`src/idns/model/`), Wire Codec (`src/idns/wire/`), Wire/Model unit tests, Raw Packet Fixtures (`tests/fixtures/`).
- **Shriyansh**: Socket Transport (`src/idns/transport/`), Iterative Engine (`src/idns/iterative/`), Referral & Glue logic, Transport/Iterative unit tests.
- **Swastik**: Cache Engine (`src/idns/cache/`), Local DNS Server (`src/idns/server/`), Observability (`src/idns/observability/`), Experiments (`experiments/`), Cache/Server unit tests.
