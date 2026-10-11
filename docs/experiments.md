# Experimental Suite & Benchmark Specification

**Owner**: Swastik + Shriyansh + Arya  
**Subsystem Directory**: `experiments/`  
**Status**: Experiments 8.1–8.4 implemented; OS integration documented.

> **Note**: The four listed experiments are implemented:
> 1. Cold vs Warm Resolution Latency
> 2. Cache Hit Ratio over Replayed Query Trace
> 3. Query Count per Resolution compared against `dig +trace`
> 4. Behavior when an Authoritative Server is Unreachable

## Cold vs. warm latency

Run repeated measurements for one domain:

```bash
PYTHONPATH=src python -m idns.cli experiment cold_warm \
  --domain example.com --record-type A --samples 5 \
  --output experiments/cold_warm/results.json
```

Cold samples clear the resolver cache before each timed resolution. Warm samples
prime the cache once, then measure cache-backed resolutions. Results contain raw
latencies in milliseconds and minimum, median, mean, and maximum summaries.

## Cache hit ratio over a replayed trace

Generate or provide a JSON array of `{ "domain": "...", "record_type": "A" }`
entries, then replay it:

```bash
PYTHONPATH=src python -m idns.cli experiment cache_hit_ratio \
  --trace-file experiments/cache_hit_ratio/query_trace.json \
  --output experiments/cache_hit_ratio/results.json
```

The report includes per-query hit/miss status, total hits and misses, and the
overall ratio (`cache_hits / total_queries`).

## Query count comparison with `dig +trace`

Compare the resolver's recorded query count with responses observed from a
local `dig +trace` run:

```bash
PYTHONPATH=src python -m idns.cli experiment query_count \
  --domain example.com --record-type A \
  --output experiments/query_count/results.json
```

The result records both counts and their difference. If `dig` is unavailable,
the report sets `dig_available` to `false` and leaves the comparison counts
as `null`.

## Unreachable authoritative server

Run this experiment; the CLI configures a deterministic unreachable
authoritative endpoint:

```bash
PYTHONPATH=src python -m idns.cli experiment unreachable_authoritative \
  --domain example.com --record-type A \
  --output experiments/unreachable_authoritative/results.json
```

The CLI installs a deterministic Root -> TLD -> authoritative scenario without
using the public network. Root and TLD return controlled referrals. The first
authoritative candidate is mapped to an unbound loopback UDP endpoint on an
ephemeral port, while the second candidate is mapped to a live loopback UDP
responder on another ephemeral port. Authoritative packets still go through the production
`UDPTransport`, so its timeout and retry policy is exercised before the
resolver fails over to Authority B.

The report includes the actual candidate endpoints attempted, UDP attempts and
retries per candidate, whether failover occurred, logical `query_count`, the
separate `query_attempt_count`, final answer/status, error details when all
candidates fail, and `elapsed_ns`/`elapsed_ms` measured from
`perf_counter_ns`. Local sockets and the responder thread are cleaned up after
each run, and the resolver's pre-experiment state is restored. A caller may
pass an explicit `TransportConfig`; otherwise the experiment uses a small
experiment-local timeout/retry configuration. `query_count` remains the
resolver's logical successful-exchange count. `query_attempt_count` is the
experiment total of the two controlled root/TLD exchanges plus every real
authoritative UDP send, including retries; `control_query_attempt_count` is
reported separately so these synthetic exchanges are not mistaken for socket
attempts.
