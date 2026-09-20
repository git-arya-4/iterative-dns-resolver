#!/usr/bin/env python3
"""
Helper script to generate query traces for cache hit ratio experiments.
"""

import json
from pathlib import Path


def generate_sample_trace(output_path: Path):
    sample_domains = [
        "example.com", "google.com", "wikipedia.org", "github.com",
        "example.com", "google.com", "iana.org", "github.com",
    ]
    trace_data = [{"domain": d, "record_type": "A"} for d in sample_domains]
    output_path.write_text(json.dumps(trace_data, indent=2))
    print(f"[IDNS TRACE] Sample query trace generated at: {output_path}")


if __name__ == "__main__":
    out_file = Path("experiments/cache_hit_ratio/query_trace.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    generate_sample_trace(out_file)
