# Experimental Suite & Benchmark Specification

**Owner**: Swastik + Shriyansh + Arya  
**Subsystem Directory**: `experiments/`  
**Status**: Cold vs warm latency implemented; remaining experiments are planned.

> **Note**: Task 8.1 implements the cold vs warm latency experiment. The remaining experiments are planned:
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
