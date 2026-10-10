"""Experiment for observing resolver behavior when an authority is unreachable."""

from __future__ import annotations

import inspect
from time import perf_counter_ns
from typing import Any, Callable

from idns.cache import InMemoryDNSCache
from idns.contracts.resolver import ResolutionContext
from idns.contracts.transport import TransportResult
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.model import ARecord, DNSHeader, DNSMessage, DNSName, NSRecord
from idns.wire import DNSMessageDecoder, DNSMessageEncoder


class _UnreachableAuthoritativeTransport:
    """Deterministic Root -> TLD -> unreachable-authority scenario."""

    def __init__(self, unreachable_ip: str) -> None:
        self.unreachable_ip = unreachable_ip

    def send_query_with_fallback(self, servers, query_bytes, config=None):
        if not servers:
            raise ServerUnreachableError("no DNS servers were provided")

        server = servers[0]
        domain = self._query_domain(query_bytes)
        qname = DNSName(domain)
        if len(qname.labels) < 2:
            raise ValueError(
                "unreachable authoritative experiment requires a domain with "
                f"at least two labels: {domain!r}"
            )

        if server.name == "test-root":
            tld = DNSName(qname.labels[-1])
            tld_server = DNSName(f"test-tld.{tld.value}")
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[NSRecord(tld, tld_server, 60)],
                additionals=[ARecord(tld_server, "192.0.2.2", 60)],
            )
        else:
            delegated_zone = DNSName(".".join(qname.labels[-2:]))
            authoritative_server = DNSName(
                f"test-authority.{delegated_zone.value}"
            )
            message = DNSMessage(
                header=DNSHeader(transaction_id=0x1234),
                authorities=[
                    NSRecord(delegated_zone, authoritative_server, 60)
                ],
                additionals=[
                    ARecord(
                        authoritative_server,
                        self.unreachable_ip,
                        60,
                    )
                ],
            )
        return TransportResult(DNSMessageEncoder.encode(message), server, 0.1)

    @staticmethod
    def _query_domain(query_bytes: bytes) -> str:
        """Extract the requested domain from the current DNS query."""
        message = DNSMessageDecoder.decode(query_bytes)
        if not message.questions:
            raise ValueError("deterministic transport received a query without a question")
        return message.questions[0].qname.value

    def send_query(self, server, query_bytes, config=None):
        raise ServerUnreachableError(
            f"authoritative server '{server.ip}:53' is unreachable"
        )


def configure_unreachable_authoritative(
    resolver: Any,
    unreachable_ip: str = "192.0.2.1",
) -> None:
    """Install the deterministic authority-failure scenario on a resolver."""
    from idns.core.cache_aware import CacheAwareResolver
    from idns.iterative.engine import IterativeEngine

    transport_config = _existing_transport_config(resolver)
    transport = _UnreachableAuthoritativeTransport(unreachable_ip)
    root_servers = [{"name": "test-root", "ipv4": "192.0.2.3"}]
    resolver.root_servers = root_servers

    # Use a fresh cache for the experiment.  The caller's cache remains attached
    # to the resolver, but cached answers cannot short-circuit the deterministic
    # root -> TLD -> authority path or be overwritten by this run.
    resolver.resolver_chain = CacheAwareResolver(
        InMemoryDNSCache(),
        IterativeEngine(
            transport,
            root_servers,
            transport_config=transport_config,
        ),
    )


def _existing_transport_config(resolver: Any) -> Any:
    """Find the resolver's current transport configuration, if any."""
    transport_config = getattr(resolver, "transport_config", None)
    if transport_config is not None:
        return transport_config

    chain = getattr(resolver, "resolver_chain", None)
    iterative_resolver = getattr(chain, "iterative_resolver", None)
    return getattr(iterative_resolver, "transport_config", None)


def _validate_experiment_domain(domain: str) -> DNSName:
    """Validate a domain that can exercise all deterministic referral stages."""
    if not isinstance(domain, str):
        raise ValueError(
            "unreachable authoritative experiment requires a DNS domain name"
        )

    try:
        qname = DNSName(domain)
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"invalid DNS domain for experiment: {domain!r}") from error

    if len(qname.labels) < 2:
        raise ValueError(
            "unreachable authoritative experiment requires a domain with "
            f"at least two labels: {domain!r}"
        )

    return qname


def _resolve_with_context(
    resolver: Any,
    domain: str,
    record_type: str,
    context: ResolutionContext,
) -> Any:
    """Call resolvers with a context when their API supports it.

    Small test doubles and older callers may only accept ``(domain, type)``;
    retaining that compatibility still lets the experiment collect metadata
    from exceptions that expose it directly.
    """
    resolve = resolver.resolve
    try:
        parameters = inspect.signature(resolve).parameters.values()
    except (TypeError, ValueError):
        return resolve(domain, record_type)

    parameter_list = list(parameters)
    context_parameter = next(
        (
            parameter
            for parameter in parameter_list
            if parameter.name == "context"
        ),
        None,
    )
    if context_parameter is not None:
        if context_parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            return resolve(domain, record_type, context)
        return resolve(domain, record_type, context=context)

    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameter_list
    ):
        return resolve(domain, record_type, context=context)

    positional_parameters = [
        parameter
        for parameter in parameter_list
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if any(
        parameter.kind is inspect.Parameter.VAR_POSITIONAL
        for parameter in parameter_list
    ) or len(positional_parameters) >= 3:
        return resolve(domain, record_type, context)

    return resolve(domain, record_type)


def _metadata_value(
    source: Any,
    context: ResolutionContext,
    attribute: str,
    default: Any,
) -> Any:
    """Read metadata from a result/error first, then the resolution context."""
    value = getattr(source, attribute, None)
    if value is not None:
        return value
    return getattr(context, attribute, default)


def _resolver_state(resolver: Any) -> dict[str, Any]:
    """Capture mutable resolver attributes changed by configuration."""
    state: dict[str, Any] = {}
    for attribute in ("root_servers", "resolver_chain"):
        state[attribute] = getattr(resolver, attribute, _MISSING)
    return state


def _restore_resolver_state(resolver: Any, state: dict[str, Any]) -> None:
    """Restore configuration changed for one experiment run."""
    for attribute, value in state.items():
        if value is _MISSING:
            try:
                delattr(resolver, attribute)
            except AttributeError:
                pass
        else:
            setattr(resolver, attribute, value)


_MISSING = object()


def run_unreachable_authoritative(
    resolver: Any,
    domain: str,
    record_type: str = "A",
    *,
    unreachable_ip: str = "192.0.2.1",
    configure_resolver: Callable[[Any, str], None] | None = None,
) -> dict[str, Any]:
    """Run a resolution against a configured unreachable endpoint.

    ``192.0.2.1`` is from TEST-NET-1 and is reserved for documentation and
    testing. A caller can provide ``configure_resolver`` to install it as the
    resolver's authoritative/root target. No retry or timeout policy is changed.
    """
    started = perf_counter_ns()
    normalized_record_type = record_type.upper()
    context = ResolutionContext()
    state = _resolver_state(resolver)
    try:
        _validate_experiment_domain(domain)
        if configure_resolver is not None:
            configure_resolver(resolver, unreachable_ip)
        result = _resolve_with_context(
            resolver,
            domain,
            normalized_record_type,
            context,
        )
    except Exception as error:
        return {
            "domain": domain,
            "record_type": normalized_record_type,
            "completed": False,
            "expected_failure": isinstance(
                error,
                (ServerUnreachableError, DNSTimeoutError, TimeoutError),
            ),
            "elapsed_ms": (perf_counter_ns() - started) / 1_000_000,
            "error_type": type(error).__name__,
            "error": str(error),
            "unreachable_endpoint": unreachable_ip,
            "query_count": int(
                _metadata_value(error, context, "query_count", 0)
            ),
            "queried_servers": list(
                _metadata_value(error, context, "queried_servers", [])
            ),
            "trace_log": list(_metadata_value(error, context, "trace_log", [])),
        }
    finally:
        _restore_resolver_state(resolver, state)

    return {
        "domain": domain,
        "record_type": normalized_record_type,
        "completed": True,
        "expected_failure": False,
        "elapsed_ms": (perf_counter_ns() - started) / 1_000_000,
        "query_count": int(
            _metadata_value(result, context, "query_count", 0)
        ),
        "queried_servers": list(
            _metadata_value(result, context, "queried_servers", [])
        ),
        "trace_log": list(_metadata_value(result, context, "trace_log", [])),
        "rcode": getattr(result, "rcode", None),
        "is_cache_hit": bool(getattr(result, "is_cache_hit", False)),
        "unreachable_endpoint": unreachable_ip,
    }
