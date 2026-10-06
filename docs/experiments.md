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
