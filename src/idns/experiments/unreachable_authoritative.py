"""Offline root -> TLD -> authority experiment using real UDP retries.

Only referrals and port mapping are synthetic. Authoritative packets use the
production UDPTransport retry loop, real sockets, and the normal wire codec.
"""

from __future__ import annotations

import inspect
import socket
import threading
from time import perf_counter_ns
from typing import Any, Callable

from idns.cache import InMemoryDNSCache
from idns.contracts.resolver import ResolutionContext
from idns.contracts.transport import ServerAddress, TransportConfig, TransportResult
from idns.errors import DNSTimeoutError, ServerUnreachableError
from idns.model import ARecord, DNSHeader, DNSMessage, DNSName, NSRecord
from idns.transport.udp import UDPTransport
from idns.wire import DNSMessageDecoder, DNSMessageEncoder


class _ObservedSocket(socket.socket):
    """Count real sends/timeouts without replacing any network operation."""

    def __init__(self, observer: _ObservedUDPTransport) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)
        self.observer = observer
        # Windows normally delivers an ICMP port-unreachable as WinError 10054.
        # Suppress that notification ONLY on experiment sockets so an unbound
        # UDP endpoint causes actual recvfrom timeouts, not immediate errors.
        # This does not change production UDPTransport's retry/error policy.
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                self.ioctl(socket.SIO_UDP_CONNRESET, False)
            except OSError:
                self.close()
                raise

    def sendto(self, data, address):
        self.observer.sent_endpoints.append(address)
        return super().sendto(data, address)

    def recvfrom(self, size):
        try:
            return super().recvfrom(size)
        except socket.timeout:
            self.observer.timeout_count += 1
            raise


class _ObservedUDPTransport(UDPTransport):
    """Inherit production send_query unchanged; only observe real sockets."""

    def __init__(self) -> None:
        self.sent_endpoints: list[tuple[str, int]] = []
        self.timeout_count = 0

    def _create_socket(self) -> socket.socket:
        return _ObservedSocket(self)


class _LocalAuthorities:
    """A has no listener; B responds on an ephemeral loopback UDP port."""

    def __init__(self, authority_b_available: bool, answer_ip: str) -> None:
        self.authority_b_available = authority_b_available
        self.answer_ip = answer_ip
        self.endpoints: list[tuple[str, int]] = []
        self.responses = 0
        self.socket: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()

    def start(self) -> None:
        if self.endpoints:
            return
        # Hold A until B is bound so the OS cannot assign them the same port.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as authority_a:
            authority_a.bind(("127.0.0.1", 0))
            authority_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                authority_b.bind(("127.0.0.1", 0))
                authority_b.settimeout(0.02)
                self.endpoints = [authority_a.getsockname(), authority_b.getsockname()]
                if self.authority_b_available:
                    self.socket = authority_b
                    self.thread = threading.Thread(
                        target=self._serve, name="idns-task-8.4-authority-b", daemon=True
                    )
                    self.thread.start()
                else:
                    authority_b.close()
            except Exception:
                authority_b.close()
                raise
        # A (and B in the exhaustion case) is now genuinely unbound.

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                packet, client = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            query = DNSMessageDecoder.decode(packet)
            response = DNSMessage(
                header=DNSHeader(transaction_id=query.header.transaction_id, qr=1, aa=1),
                questions=query.questions,
                answers=[ARecord(query.questions[0].qname, self.answer_ip, 60)],
            )
            self.socket.sendto(DNSMessageEncoder.encode(response), client)
            self.responses += 1

    def close(self) -> None:
        self.stop.set()
        try:
            if self.thread is not None:
                self.thread.join(timeout=1.0)
                if self.thread.is_alive():
                    raise RuntimeError("local authority responder did not stop")
        finally:
            if self.socket is not None:
                self.socket.close()


class _UnreachableAuthoritativeTransport:
    """Controlled referrals, plus a name-to-port adapter for real authority UDP."""

    def __init__(
        self,
        unreachable_ip: str,
        authority_b_available: bool,
        answer_ip: str,
    ) -> None:
        # TEST-NET addresses occur in referral bytes only; no packet uses them.
        self.unreachable_ip = unreachable_ip
        self.authorities = _LocalAuthorities(authority_b_available, answer_ip)
        self.udp = _ObservedUDPTransport()
        self.control_query_attempt_count = 0
        self.candidate_attempts: list[dict[str, Any]] = []

    def send_query_with_fallback(self, servers, query_bytes, config=None):
        if not servers:
            raise ServerUnreachableError("no DNS servers were provided")
        self.authorities.start()
        query = DNSMessageDecoder.decode(query_bytes)
        qname = query.questions[0].qname
        header = DNSHeader(transaction_id=query.header.transaction_id, qr=1)
        if servers[0].name == "test-root":
            zone = DNSName(qname.labels[-1])
            nameservers = [DNSName(f"test-tld.{zone.value}")]
            addresses = ["192.0.2.2"]
        elif servers[0].name == f"test-tld.{qname.labels[-1]}":
            zone = DNSName(".".join(qname.labels[-2:]))
            nameservers = [DNSName(f"authority-{letter}.{zone.value}") for letter in "ab"]
            addresses = [self.unreachable_ip, "192.0.2.4"]
        else:
            raise ValueError("unexpected controlled root/TLD candidate")
        message = DNSMessage(
            header=header,
            questions=query.questions,
            authorities=[NSRecord(zone, name, 60) for name in nameservers],
            additionals=[ARecord(name, ip, 60) for name, ip in zip(nameservers, addresses)],
        )
        self.control_query_attempt_count += 1
        return TransportResult(DNSMessageEncoder.encode(message), servers[0], 0.0)

    def send_query(self, server, query_bytes, config=None):
        self.authorities.start()
        prefix = (server.name or "").split(".", 1)[0]
        if prefix not in ("authority-a", "authority-b"):
            raise ValueError("unexpected authoritative candidate")
        ip, port = self.authorities.endpoints[prefix == "authority-b"]
        mapped = ServerAddress(ip, port, name=server.name)
        attempts_before = len(self.udp.sent_endpoints)
        timeouts_before = self.udp.timeout_count
        started = perf_counter_ns()
        entry = {"name": server.name, "endpoint": f"{ip}:{port}", "started_ns": started,
                 "succeeded": False, "error_type": None, "error": None}
        self.candidate_attempts.append(entry)
        try:
            # No retry logic here: every attempt is made by production send_query.
            result = self.udp.send_query(mapped, query_bytes, config)
            entry["succeeded"] = True
            return result
        except Exception as error:
            entry["error_type"] = type(error).__name__
            entry["error"] = str(error)
            raise
        finally:
            finished = perf_counter_ns()
            attempts = len(self.udp.sent_endpoints) - attempts_before
            entry.update(udp_attempts=attempts, retries=max(0, attempts - 1),
                         timeouts=self.udp.timeout_count - timeouts_before,
                         finished_ns=finished, elapsed_ns=finished - started)

    def close(self) -> None:
        self.authorities.close()

    def snapshot(self) -> dict[str, Any]:
        candidates = self.candidate_attempts
        return {
            "unreachable_endpoint": (
                f"{self.authorities.endpoints[0][0]}:{self.authorities.endpoints[0][1]}"
                if self.authorities.endpoints else self.unreachable_ip
            ),
            "candidate_endpoints_attempted": [entry["endpoint"] for entry in candidates],
            "candidate_names_attempted": [entry["name"] for entry in candidates],
            "candidate_attempts": [dict(entry) for entry in candidates],
            "udp_attempts": {entry["name"]: entry["udp_attempts"] for entry in candidates},
            "retries_per_candidate": {entry["name"]: entry["retries"] for entry in candidates},
            "failover_occurred": len(candidates) > 1 and not candidates[0]["succeeded"],
            "candidate_exhausted": len(candidates) == 2 and not any(
                entry["succeeded"] for entry in candidates
            ),
            "control_query_attempt_count": self.control_query_attempt_count,
            "query_attempt_count": self.control_query_attempt_count + len(self.udp.sent_endpoints),
            "authority_b_responses": self.authorities.responses,
        }


def _existing_transport_config(resolver: Any) -> TransportConfig | None:
    """Find the resolver's current transport configuration, if available."""
    configured = getattr(resolver, "transport_config", None)
    if configured is not None:
        return configured
    chain = getattr(resolver, "resolver_chain", None)
    iterative = getattr(chain, "iterative_resolver", None)
    return getattr(iterative, "transport_config", None)


def configure_unreachable_authoritative(
    resolver: Any,
    unreachable_ip: str = "192.0.2.1",
    *,
    transport_config: TransportConfig | None = None,
    authority_b_available: bool = True,
    answer_ip: str = "203.0.113.42",
) -> _UnreachableAuthoritativeTransport:
    """Install the deterministic Task 8.4 scenario on ``resolver``."""
    from idns.core.cache_aware import CacheAwareResolver
    from idns.iterative.engine import IterativeEngine

    effective_config = transport_config or _existing_transport_config(resolver)
    if effective_config is None:
        effective_config = TransportConfig(
            timeout_seconds=0.02,
            max_retries=1,
            enable_tcp_fallback=False,
            buffer_size=1232,
        )

    transport = _UnreachableAuthoritativeTransport(
        unreachable_ip=unreachable_ip,
        authority_b_available=authority_b_available,
        answer_ip=answer_ip,
    )
    roots = [{"name": "test-root", "ipv4": "192.0.2.3"}]
    resolver.root_servers = roots
    resolver.resolver_chain = CacheAwareResolver(
        InMemoryDNSCache(),
        IterativeEngine(transport, roots, transport_config=effective_config),
    )
    return transport


def _validate_domain(domain: str) -> DNSName:
    if not isinstance(domain, str):
        raise ValueError("unreachable authoritative experiment requires a DNS domain name")
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
    """Call both current and legacy resolver signatures."""
    resolve = resolver.resolve
    try:
        parameters = list(inspect.signature(resolve).parameters.values())
    except (TypeError, ValueError):
        return resolve(domain, record_type)

    if any(parameter.name == "context" for parameter in parameters):
        parameter = next(parameter for parameter in parameters if parameter.name == "context")
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            return resolve(domain, record_type, context)
        return resolve(domain, record_type, context=context)
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters):
        return resolve(domain, record_type, context=context)
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters) or len(positional) >= 3:
        return resolve(domain, record_type, context)
    return resolve(domain, record_type)


def _resolver_state(resolver: Any) -> dict[str, Any]:
    missing = object()
    return {
        "root_servers": getattr(resolver, "root_servers", missing),
        "resolver_chain": getattr(resolver, "resolver_chain", missing),
        "missing": missing,
    }


def _restore_resolver_state(resolver: Any, state: dict[str, Any]) -> None:
    missing = state["missing"]
    for attribute in ("root_servers", "resolver_chain"):
        value = state[attribute]
        if value is missing:
            try:
                delattr(resolver, attribute)
            except AttributeError:
                pass
        else:
            setattr(resolver, attribute, value)


def _find_transport(resolver: Any, configured: Any) -> _UnreachableAuthoritativeTransport | None:
    if isinstance(configured, _UnreachableAuthoritativeTransport):
        return configured
    chain = getattr(resolver, "resolver_chain", None)
    transport = getattr(getattr(chain, "iterative_resolver", None), "transport", None)
    return transport if isinstance(transport, _UnreachableAuthoritativeTransport) else None


def _metadata(source: Any, context: ResolutionContext, name: str, default: Any) -> Any:
    value = getattr(source, name, None)
    return default if value is None and not hasattr(context, name) else (
        getattr(context, name, default) if value is None else value
    )


def _record_dict(record: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": getattr(getattr(record, "name", None), "value", None),
        "record_type": getattr(record, "record_type", type(record).__name__),
        "ttl": getattr(record, "ttl", None),
    }
    for attribute in ("address", "canonical_name", "nameserver", "exchange"):
        if hasattr(record, attribute):
            item = getattr(record, attribute)
            value[attribute] = getattr(item, "value", item)
    return value


def _invoke_configure(callback: Callable[..., Any], resolver: Any, unreachable_ip: str, **options: Any) -> Any:
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return callback(resolver, unreachable_ip)
    accepts_kwargs = any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values())
    kwargs = {
        name: value
        for name, value in options.items()
        if name in parameters or accepts_kwargs
    }
    return callback(resolver, unreachable_ip, **kwargs)


def run_unreachable_authoritative(
    resolver: Any,
    domain: str,
    record_type: str = "A",
    *,
    unreachable_ip: str = "192.0.2.1",
    configure_resolver: Callable[..., Any] | None = None,
    transport_config: TransportConfig | None = None,
    authority_b_available: bool = True,
    answer_ip: str = "203.0.113.42",
) -> dict[str, Any]:
    """Run Task 8.4 and return JSON-safe retry/failover evidence.

    ``query_count`` retains the resolver's logical successful-exchange count.
    ``query_attempt_count`` is experiment-level and includes every UDP send,
    including retries and the two controlled root/TLD exchanges.
    """
    started = perf_counter_ns()
    normalized_type = record_type.upper()
    context = ResolutionContext()
    state = _resolver_state(resolver)
    configured: Any = None
    transport: _UnreachableAuthoritativeTransport | None = None
    result: Any = None
    error: Exception | None = None

    try:
        _validate_domain(domain)
        # Keep legacy resolver doubles usable when no configuration callback is
        # supplied; CoreResolver-like objects get the deterministic default.
        should_configure = configure_resolver is not None or hasattr(resolver, "resolver_chain")
        if should_configure:
            callback = configure_resolver or configure_unreachable_authoritative
            configured = _invoke_configure(
                callback,
                resolver,
                unreachable_ip,
                transport_config=transport_config,
                authority_b_available=authority_b_available,
                answer_ip=answer_ip,
            )
            transport = _find_transport(resolver, configured)
        result = _resolve_with_context(resolver, domain, normalized_type, context)
    except Exception as caught:
        error = caught
    finally:
        if transport is None:
            transport = _find_transport(resolver, configured)
        snapshot = transport.snapshot() if transport is not None else None
        if transport is not None:
            transport.close()
        _restore_resolver_state(resolver, state)

    elapsed_ns = perf_counter_ns() - started
    if snapshot is None:
        snapshot = {
            "unreachable_endpoint": unreachable_ip,
            "candidate_endpoints_attempted": [],
            "candidate_names_attempted": [],
            "candidate_attempts": [],
            "udp_attempts": {},
            "retries_per_candidate": {},
            "failover_occurred": False,
            "candidate_exhausted": False,
            "query_attempt_count": 0,
            "authority_b_responses": 0,
        }

    source = result if error is None else error
    query_count = int(_metadata(source, context, "query_count", 0))
    query_attempt_count = int(_metadata(source, context, "query_attempt_count", snapshot["query_attempt_count"]))
    answers = list(getattr(result, "answers", []) or [])
    return {
        "domain": domain,
        "record_type": normalized_type,
        "unreachable_endpoint": snapshot["unreachable_endpoint"],
        "unreachable_ip": unreachable_ip,
        "candidate_endpoints_attempted": snapshot["candidate_endpoints_attempted"],
        "candidate_names_attempted": snapshot["candidate_names_attempted"],
        "candidate_attempts": snapshot["candidate_attempts"],
        "udp_attempts": snapshot["udp_attempts"],
        "retries_per_candidate": snapshot["retries_per_candidate"],
        "failover_occurred": snapshot["failover_occurred"],
        "candidate_exhausted": snapshot["candidate_exhausted"],
        "completed": error is None,
        "final_success": error is None,
        "final_failure": error is not None,
        "final_status": "success" if error is None else "failure",
        "expected_failure": isinstance(error, (ServerUnreachableError, DNSTimeoutError, TimeoutError)),
        "error_type": type(error).__name__ if error is not None else None,
        "error_message": str(error) if error is not None else None,
        "error": str(error) if error is not None else None,
        "elapsed_ns": elapsed_ns,
        "elapsed_ms": elapsed_ns / 1_000_000,
        "query_count": query_count,
        "query_attempt_count": query_attempt_count,
        "control_query_attempt_count": snapshot["control_query_attempt_count"]
        if "control_query_attempt_count" in snapshot
        else 0,
        "query_attempt_count_semantics": (
            "controlled root/TLD exchanges plus every authoritative UDP send, "
            "including retries"
        ),
        "queried_servers": list(_metadata(source, context, "queried_servers", [])),
        "trace_log": list(_metadata(source, context, "trace_log", [])),
        "rcode": getattr(result, "rcode", None) if result is not None else None,
        "is_cache_hit": bool(getattr(result, "is_cache_hit", False)) if result is not None else False,
        "answer_count": len(answers),
        "final_answers": [_record_dict(answer) for answer in answers],
        "authority_b_responses": snapshot["authority_b_responses"],
    }
