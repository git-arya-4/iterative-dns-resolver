"""Cache hit-ratio experiment over a replayed JSON query trace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def load_trace(path: str | Path) -> list[dict[str, str]]:
    """Load and validate a trace containing domain and record_type fields."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid query trace: {path}") from error
    if not isinstance(data, list):
        raise ValueError("query trace must be a JSON array")

    trace: list[dict[str, str]] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("domain"), str):
            raise ValueError(f"trace entry {index} must contain a string domain")
        record_type = item.get("record_type", "A")
        if not isinstance(record_type, str) or not record_type.strip():
            raise ValueError(f"trace entry {index} must contain a valid record_type")
        trace.append({"domain": item["domain"], "record_type": record_type.upper()})
    return trace


def run_cache_hit_ratio(
    resolver: Any,
    trace: Iterable[dict[str, str]],
) -> dict[str, Any]:
    """Replay a trace against one resolver and calculate cache hit ratio."""
    entries = list(trace)
    hits = 0
    queries: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        domain = entry["domain"]
        record_type = entry.get("record_type", "A").upper()
        result = resolver.resolve(domain, record_type)
        cache_hit = bool(getattr(result, "is_cache_hit", False))
        hits += cache_hit
        queries.append(
            {
                "index": index,
                "domain": domain,
                "record_type": record_type,
                "cache_hit": cache_hit,
            }
        )

    total = len(entries)
    return {
        "total_queries": total,
        "cache_hits": hits,
        "cache_misses": total - hits,
        "hit_ratio": hits / total if total else 0.0,
        "queries": queries,
    }
