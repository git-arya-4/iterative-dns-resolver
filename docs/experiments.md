# Experimental Suite & Benchmark Suite

**Owner**: Swastik + Shriyansh + Arya  
**Subsystem Directory**: `experiments/`  
**Status**: Implemented in `src/idns/experiments.py`

The CLI provides four reproducible modes:

1. `cold_warm` measures a fresh-cache query and a repeated query with `time.perf_counter()`.
2. `cache_hit_ratio` replays a configurable query sequence and counts each returned `ResolverResult.is_cache_hit` value.
3. `query_count` reports the resolver's logical root/TLD/authoritative exchange count for cold and warm queries. UDP retry attempts are not included.
4. `unreachable_authoritative` is a deterministic controlled simulation with two unreachable authoritative glue addresses, exercising real resolver failover logic.

The first three modes use the production resolver and may require reachable DNS infrastructure. They return a non-zero status with an explicit error if resolution fails. Add `--csv PATH` to save machine-readable output; `--domain`, `--record-type`, and `--repetitions` are also available where applicable.
