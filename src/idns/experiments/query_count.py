"""Compare resolver query counts with ``dig +trace``."""

from __future__ import annotations

import re
import subprocess
from typing import Any, Callable


_DIG_RESPONSE = re.compile(r"^;;\s+Received\s+\d+\s+bytes\s+from\s+", re.MULTILINE)


def count_dig_trace_responses(output: str) -> int:
    """Count DNS responses printed by dig's ``+trace`` mode."""
    return len(_DIG_RESPONSE.findall(output))


def run_query_count_comparison(
    resolver: Any,
    domain: str,
    record_type: str = "A",
    *,
    dig_command: str = "dig",
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Compare one resolver result with a local ``dig +trace`` invocation."""
    record_type = record_type.upper()
    result = resolver.resolve(domain, record_type)
    resolver_count = int(getattr(result, "query_count", 0))

    try:
        completed = runner(
            [dig_command, "+trace", domain, record_type],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, FileNotFoundError) as error:
        return {
            "domain": domain,
            "record_type": record_type,
            "resolver_query_count": resolver_count,
            "dig_trace_query_count": None,
            "difference": None,
            "dig_available": False,
            "dig_error": str(error),
        }

    output = f"{completed.stdout}\n{completed.stderr}"
    dig_count = count_dig_trace_responses(output)
    return {
        "domain": domain,
        "record_type": record_type,
        "resolver_query_count": resolver_count,
        "dig_trace_query_count": dig_count,
        "difference": resolver_count - dig_count,
        "dig_available": completed.returncode == 0,
        "dig_return_code": completed.returncode,
    }
