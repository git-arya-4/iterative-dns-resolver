# Architecture & Design Specification

**Project**: Iterative DNS Resolver with Caching (`iterative-dns-resolver`)  
**Author**: Arya (Project Lead & Core Systems Integrator)  

---

## 1. Single Package Architecture (`src/idns/`)

The runtime code is consolidated under a single Python package (`src/idns/`) to ensure clean imports and eliminate duplicate root-level modules.

```
iterative-dns-resolver/
│
├── config/                  [Arya] Root hints & configuration templates
├── docs/                    [All] Architecture and module specifications
├── experiments/             [Swastik] Benchmark scripts and trace logs
├── scripts/                 [Arya] Helper scripts for running resolver/server
│
├── src/idns/
│   ├── cli.py               [Arya] Command line interface
│   ├── errors.py            [Arya] Exception hierarchy
│   ├── contracts/           [Arya] Stable interfaces (codec, transport, cache, resolver)
│   ├── core/                [Arya] Core resolver orchestrator & CNAME processor
│   ├── model/               [Avidipta] DNS Header, Question, RR, RDATA types
│   ├── wire/                [Avidipta] RFC 1035 hand-crafted Codec & Compression
│   ├── transport/           [Shriyansh] Sockets, UDP, Retry, Timeout, TCP Fallback
│   ├── iterative/           [Shriyansh] Root->TLD->Auth Referrals, Glue, Bootstrap
│   ├── cache/               [Swastik] TTL Eviction, RFC 2308 Negative Cache
│   ├── server/              [Swastik/Arya/Avidipta] Local DNS server daemon
│   ├── observability/       [Swastik] Metrics and tracing infrastructure
│   └── extensions/          [All] Stretch features (EDNS0, DNSSEC)
│
└── tests/
    └── unit/                [All] Unit tests for contracts, errors, CLI, core
```

---

## 2. Dependency Flow Architecture

To prevent circular imports, code dependencies flow strictly in one direction:

```
                 ARYA
           idns.contracts
                 │
                 ▼
              AVIDIPTA
             idns.model
                 │
         ┌───────┴───────┐
         ▼               ▼
     AVIDIPTA         SHRIYANSH
    idns.wire       idns.transport
         │               │
         └───────┬───────┘
                 ▼
             SHRIYANSH
          idns.iterative
                 │
         ┌───────┴───────┐
         ▼               ▼
      SWASTIK           ARYA
    idns.cache          CNAME
         │               │
         └───────┬───────┘
                 ▼
                ARYA
             idns.core
                 │
                 ▼
              SWASTIK
            idns.server
                 │
                 ▼
            ALL MEMBERS
            integration
                 │
                 ▼
              SWASTIK
            experiments
                 │
                 ▼
            ALL MEMBERS
            validation
```

---

## 3. Team Phase Dependency Gates

1. **Gate 1**: Avidipta stabilizes `idns.model` (Header, Question, ResourceRecord).
2. **Gate 2**: Avidipta completes `idns.wire` (Codec) and Shriyansh completes `idns.transport` (Sockets).
3. **Gate 3**: Shriyansh completes `idns.iterative` (Root -> TLD -> Auth referral traversal).
4. **Gate 4**: Arya integrates Cache (Swastik), Iterative Resolver (Shriyansh), and CNAME processor into `idns.core`. Unblocks `idns.server` and experiments.
