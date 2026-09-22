"""
CLI Scaffolding for Iterative DNS Resolver.

Provides CLI entry points for query testing, server operation, and experiments.
"""

import argparse
import sys
from pathlib import Path

from idns.core import CoreResolverScaffold
from idns.errors import DNSError


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="idns-resolver",
        description="Iterative DNS Resolver with Caching (P2 Networking Project)",
    )
    
    parser.add_argument(
        "--config",
        type=str,
        default="config/root_hints.json",
        help="Path to root hints JSON configuration file (default: config/root_hints.json)",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0-foundation",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: resolve
    resolve_parser = subparsers.add_parser("resolve", help="Query a domain name using iterative resolution")
    resolve_parser.add_argument("domain", help="Domain FQDN to resolve (e.g. example.com)")
    resolve_parser.add_argument(
        "-t", "--type",
        default="A",
        choices=["A", "AAAA", "NS", "CNAME", "MX", "TXT", "SOA"],
        help="DNS record type to query (default: A)",
    )
    resolve_parser.add_argument("--trace", action="store_true", help="Print iterative resolution step trace")

    # Command: server
    server_parser = subparsers.add_parser("server", help="Run local DNS server daemon")
    server_parser.add_argument("-p", "--port", type=int, default=5353, help="Port to listen on (default: 5353)")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")

    # Command: experiment
    exp_parser = subparsers.add_parser("experiment", help="Run project experiment suite")
    exp_parser.add_argument(
        "name",
        choices=["cold_warm", "cache_hit_ratio", "query_count", "unreachable_authoritative"],
        help="Name of experiment to execute",
    )

    return parser


def main(args: list[str] | None = None) -> int:
    """CLI execution entry point."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    try:
        # Instantiate core scaffold to verify root hints loading
        hints_path = Path(parsed_args.config)
        scaffold = CoreResolverScaffold(root_hints_path=hints_path if hints_path.exists() else None)
        
        if parsed_args.command == "resolve":
            print(f"[IDNS CLI] Resolving '{parsed_args.domain}' (Type: {parsed_args.type})...")
            print(
                "[IDNS CLI] Note: Core iterative resolution algorithm will be integrated in Phase 5.\n"
                "           Root hints configuration loaded successfully."
            )
            return 0
        elif parsed_args.command == "server":
            print(f"[IDNS CLI] Starting local DNS server on {parsed_args.host}:{parsed_args.port}...")
            print("[IDNS CLI] Note: Local DNS server module is scheduled for implementation in Phase 6.")
            return 0
        elif parsed_args.command == "experiment":
            print(f"[IDNS CLI] Running experiment trace '{parsed_args.name}'...")
            print("[IDNS CLI] Note: Experiment harness is scheduled for execution in Phase 8.")
            return 0

    except DNSError as e:
        print(f"[IDNS ERROR] {e.message}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[IDNS UNEXPECTED ERROR] {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
