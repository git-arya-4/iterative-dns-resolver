"""Command-line entry points for the iterative DNS resolver."""

import argparse
import sys
from pathlib import Path

from idns.cache import InMemoryDNSCache
from idns.contracts import ResolutionContext, ResolverResult
from idns.core import CoreResolver, SUPPORTED_RECORD_TYPES
from idns.errors import ConfigError, DNSError
from idns.server import TCPDNSServer, UDPDNSServer
from idns.transport.udp import UDPTransport


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
        version="%(prog)s 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: resolve
    resolve_parser = subparsers.add_parser("resolve", help="Query a domain name using iterative resolution")
    resolve_parser.add_argument("domain", help="Domain FQDN to resolve (e.g. example.com)")
    resolve_parser.add_argument(
        "record_type",
        nargs="?",
        type=str.upper,
        choices=SUPPORTED_RECORD_TYPES,
        help="DNS record type (default: A)",
    )
    resolve_parser.add_argument(
        "-t", "--type",
        dest="type_option",
        type=str.upper,
        choices=SUPPORTED_RECORD_TYPES,
        default=None,
        help="DNS record type to query (default: A)",
    )
    resolve_parser.add_argument("--trace", action="store_true", help="Print iterative resolution step trace")

    # Command: server
    server_parser = subparsers.add_parser("server", help="Run local DNS server daemon")
    server_parser.add_argument("-p", "--port", type=int, default=5353, help="Port to listen on (default: 5353)")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    server_parser.add_argument("--tcp", action="store_true", help="Use DNS-over-TCP instead of UDP")

    # Command: experiment
    exp_parser = subparsers.add_parser("experiment", help="Run project experiment suite")
    exp_parser.add_argument(
        "name",
        choices=["cold_warm", "cache_hit_ratio", "query_count", "unreachable_authoritative"],
        help="Name of experiment to execute",
    )

    return parser


def _format_record(record: object) -> str:
    record_type = getattr(record, "record_type", type(record).__name__)
    name = getattr(getattr(record, "name", None), "value", "?")
    ttl = getattr(record, "ttl", "?")
    details = []
    for attribute in ("address", "canonical_name", "nameserver", "preference", "exchange", "text", "mname", "rname", "serial", "minimum"):
        if hasattr(record, attribute):
            value = getattr(record, attribute)
            details.append(getattr(value, "value", value))
    suffix = " ".join(str(value) for value in details)
    return f"{name} {ttl} IN {record_type}" + (f" {suffix}" if suffix else "")


def _print_result(result: ResolverResult, trace: bool) -> None:
    print(f"Query: {result.domain_name} {result.record_type}")
    print(f"Status: {'NXDOMAIN' if result.is_nxdomain else f'RCODE={result.rcode}'}")
    print(f"Cache: {'hit' if result.is_cache_hit else 'miss'}")
    print(f"Queries: {result.query_count}")
    if result.answers:
        print("Answers:")
        for record in result.answers:
            print(f"  {_format_record(record)}")
    else:
        print("Answers: (none)")
    if result.cname_chain:
        print(f"CNAME chain: {' -> '.join(result.cname_chain)}")
    if trace:
        print("Trace:")
        for event in getattr(result, "trace_log", []):
            print(f"  {event}")


def main(args: list[str] | None = None) -> int:
    """CLI execution entry point."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    try:
        hints_path = Path(parsed_args.config)
        if not hints_path.is_file():
            raise ConfigError(f"Root hints file not found at: {hints_path}")

        resolver = CoreResolver(
            root_hints_path=hints_path,
            transport=UDPTransport(),
            cache=InMemoryDNSCache(),
        )

        if parsed_args.command == "resolve":
            record_type = parsed_args.type_option or parsed_args.record_type or "A"
            context = ResolutionContext()
            result = resolver.resolve(parsed_args.domain, record_type, context)
            _print_result(result, parsed_args.trace)
            return 0
        elif parsed_args.command == "server":
            print(f"[IDNS CLI] Starting local DNS server on {parsed_args.host}:{parsed_args.port}...")
            server_type = TCPDNSServer if parsed_args.tcp else UDPDNSServer
            server_type(resolver, host=parsed_args.host, port=parsed_args.port).serve_forever()
            return 0
        elif parsed_args.command == "experiment":
            print("experiment mode is not yet implemented", file=sys.stderr)
            return 2

    except DNSError as e:
        print(f"[IDNS ERROR] {e.message}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[IDNS UNEXPECTED ERROR] {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
