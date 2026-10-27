# Reproducible validation artifacts

These directories contain JSON measurements and dependency-free SVG graphs
captured from the resolver implementation.

From the repository root:

```bash
PYTHONPATH=src python scripts/generate_query_trace.py
PYTHONPATH=src python -m idns.cli experiment cold_warm \
  --domain example.com --record-type A --samples 3 \
  --output experiments/cold_warm/results.json
PYTHONPATH=src python -m idns.cli experiment cache_hit_ratio \
  --trace-file experiments/cache_hit_ratio/query_trace.json \
  --output experiments/cache_hit_ratio/results.json
PYTHONPATH=src python -m idns.cli experiment query_count \
  --domain example.com --record-type A \
  --output experiments/query_count/results.json
PYTHONPATH=src python -m idns.cli experiment unreachable_authoritative \
  --domain example.com --record-type A \
  --output experiments/unreachable_authoritative/results.json
PYTHONPATH=src python scripts/generate_experiment_graphs.py
```

`os_integration/results.json` records a local port-53 `nslookup` check and a
real HTTPS request made using an address obtained from that local server.
The browse-web validation script can regenerate this artifact:

```bash
PYTHONPATH=src python scripts/browse_web_test.py \
  --domain example.com \
  --output experiments/os_integration/results.json
```
`end_to_end/record_types.json` records live root-to-authority checks for A,
AAAA, NS, MX, TXT, SOA, and CNAME. Query-count comparison is approximate by
definition; `query_count/results_dig.json` records the sandbox Linux
`dig +trace` comparison and its raw output in `dig_trace.txt`.
