"""Task 9.3: Validate resolver behavior against live DNS.

This opt-in system check exercises A/AAAA resolution, cache reuse, and an
expected NXDOMAIN response using the configured root hints. It makes DNS
queries to the public Internet and is never run as part of the unit suite.

Usage from the repository root::

    $env:PYTHONPATH = "src"
    python scripts/live_robustness_validation.py
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from idns.cache import InMemoryDNSCache
from idns.core import CoreResolver
from idns.transport.udp import UDPTransport


def _summarize(result) -> dict:
    return {
        "rcode": result.rcode,
        "answer_count": len(result.answers),
        "answer_types": sorted({getattr(answer, "record_type", "unknown") for answer in result.answers}),
        "query_count": result.query_count,
        "cache_hit": result.is_cache_hit,
        "is_nxdomain": result.is_nxdomain,
        "is_nodata": result.is_nodata,
    }


def run(domain: str, negative_domain: str, root_hints: Path) -> dict:
    resolver = CoreResolver(
        root_hints_path=root_hints,
        transport=UDPTransport(),
        cache=InMemoryDNSCache(),
    )
    checks = []

    for record_type in ("A", "AAAA"):
        started = time.perf_counter()
        try:
            result = resolver.resolve(domain, record_type)
            check = {"name": f"{domain} {record_type}", "status": "ok", **_summarize(result)}
            if result.rcode != 0:
                check.update(status="fail", error=f"unexpected rcode {result.rcode}")
            elif not result.answers and not result.is_nodata:
                check.update(status="fail", error="empty answer without NODATA proof")
        except Exception as exc:
            check = {"name": f"{domain} {record_type}", "status": "fail", "error": str(exc)}
        check["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
        checks.append(check)

    # A second A lookup confirms that a successful result is served from cache.
    started = time.perf_counter()
    try:
        repeated = resolver.resolve(domain, "A")
        check = {"name": f"{domain} A cache repeat", "status": "ok", **_summarize(repeated)}
        if not repeated.is_cache_hit:
            check.update(status="fail", error="repeat query did not use cache")
    except Exception as exc:
        check = {"name": f"{domain} A cache repeat", "status": "fail", "error": str(exc)}
    check["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    checks.append(check)

    started = time.perf_counter()
    try:
        negative = resolver.resolve(negative_domain, "A")
        check = {"name": f"{negative_domain} NXDOMAIN", "status": "ok", **_summarize(negative)}
        if not negative.is_nxdomain:
            check.update(status="fail", error="expected NXDOMAIN for reserved .invalid domain")
    except Exception as exc:
        check = {"name": f"{negative_domain} NXDOMAIN", "status": "fail", "error": str(exc)}
    check["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    checks.append(check)

    return {
        "root_hints": str(root_hints),
        "live_internet": True,
        "checks": checks,
        "passed": all(check["status"] == "ok" for check in checks),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run opt-in live DNS robustness checks")
    parser.add_argument("--domain", default="example.com", help="Known live domain to query (default: example.com)")
    parser.add_argument("--negative-domain", default="idns-task-9-3.invalid", help="Reserved .invalid name expected to return NXDOMAIN")
    parser.add_argument("--root-hints", type=Path, default=Path("config/root_hints.json"))
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    report = run(args.domain, args.negative_domain, args.root_hints)
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
