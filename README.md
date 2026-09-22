# Iterative DNS Resolver with Caching (`iterative-dns-resolver`)

[![CI](https://github.com/git-arya-4/iterative-dns-resolver/actions/workflows/ci.yml/badge.svg)](https://github.com/git-arya-4/iterative-dns-resolver/actions/workflows/ci.yml)

> **Computer Networks Project 2 (P2) — Socket-Level DNS Protocol Implementation**  
> **Course**: Computer Networks (Coding Assignment 1)  
> **Team**: Arya (Lead), Avidipta, Shriyansh, Swastik (Team size: 4)  
> **Repository**: `git-arya-4/iterative-dns-resolver`  

---

## 1. Project Overview & Academic Purpose

This project is a hand-crafted, socket-level **Iterative DNS Resolver with Caching** written in Python for Computer Networks P2.

### Primary Academic Constraints & Rules
- **Socket-Level Networking**: All DNS wire protocol encoding, decoding, compression, and network transport are written manually at the socket layer.
- **Strict Prohibition of Third-Party DNS Libraries**:
  - ❌ `dnspython` is **BANNED**
  - ❌ `miekg/dns` / `dnsjava` are **BANNED**
  - ❌ `socket.getaddrinfo()` for actual DNS resolution is **BANNED**
- **Zero Forwarding**: Full iterative resolution starts directly from root hints (`Root -> TLD -> Authoritative`). Forwarding queries to public recursive resolvers (e.g. `8.8.8.8`, `1.1.1.1`) is strictly **BANNED**.

---

## 2. Core Mandatory Requirements

1. **Wire Format Encoding & Decoding**: Hand-crafted RFC 1035 parser and serializer.
2. **Name Compression**: Full parsing and generation of DNS compression pointers (`0xC0` byte prefix).
3. **Iterative Hierarchy**: `Root -> TLD -> Authoritative` referral traversal.
4. **Supported Record Types**: `A`, `AAAA`, `NS`, `CNAME`, `MX`, `TXT`, `SOA`.
5. **Glue & CNAME Resolution**: Resolution of out-of-bailiwick glue records and multi-step CNAME alias chains.
6. **UDP Transport**: Custom retry, timeout, and candidate server selection algorithms.
7. **TCP Fallback**: Automatic TCP retry when response Truncation bit (`TC=1`) is set.
8. **Caching Engine**:
   - TTL-based eviction
   - RFC 2308 negative caching (NXDOMAIN & NODATA)
   - CNAME loop protection and depth controls
9. **OS Integration**: Local DNS server daemon accepting OS resolver queries and browser web traffic.
10. **Experimental Suite**:
   - Cold vs. warm resolution latency
   - Cache hit ratio over replayed query traces
   - Query count per resolution compared against `dig +trace`
   - Resiliency when an authoritative server is unreachable

---

## 3. Team Ownership & Architecture

All Python runtime code lives strictly inside `src/idns/`:

```
src/idns/
├── cli.py               [Arya] CLI argument parser & subcommand scaffold
├── errors.py            [Arya] Unified exception hierarchy
├── contracts/           [Arya] Stable interfaces & types (NO protocol logic)
├── core/                [Arya] Resolver orchestrator & CNAME processor
├── model/               [Avidipta] DNS Header, Question, RR, RDATA types
├── wire/                [Avidipta] RFC 1035 hand-crafted Codec & Compression
├── transport/           [Shriyansh] Sockets, UDP, Retry, Timeout, TCP Fallback
├── iterative/           [Shriyansh] Root->TLD->Auth Referrals, Glue, Bootstrap
├── cache/               [Swastik] TTL Eviction, RFC 2308 Negative Cache
├── server/              [Swastik/Arya/Avidipta] Local DNS server port 53 daemon
├── observability/       [Swastik] Metrics and tracing infrastructure
└── extensions/          [All] Stretch features (EDNS0, DNSSEC)
```

---

## 4. Quick Start & Setup

### Environment Setup
```bash
# Clone the repository
git clone https://github.com/git-arya-4/iterative-dns-resolver.git
cd iterative-dns-resolver

# Install in editable mode with development tools
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest -v
```

### CLI Command Foundation
```bash
# Display CLI help
idns-resolver --help

# Query command scaffold
idns-resolver resolve example.com -t A

# Local DNS server scaffold
idns-resolver server --port 5353
```

---

## 5. Current Project Stage

> **Current Phase**: **Phase 0 (Foundation - Tasks 0.1 to 0.4)**  
> All stable contracts, exception hierarchies, directory skeletons under `src/idns/`, CI pipelines, root hints configurations, and foundation tests are established. Core DNS protocol logic will be implemented incrementally by subsystem owners in subsequent phases.
