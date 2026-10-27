"""
Top-level iterative DNS resolution engine.
"""

from typing import Optional
from idns.contracts.resolver import DNSResolverProtocol, ResolutionContext, ResolverResult
from idns.contracts.transport import DNSTransportProtocol, TransportConfig, ServerAddress
from idns.model import DNSName, DNSMessage, NSRecord, OPTRecord
from idns.iterative.root_query import RootQuery
from idns.iterative.tld_query import TLDQuery
from idns.iterative.authoritative_query import AuthoritativeQuery
from idns.iterative.referral import ReferralParser
from idns.iterative.glue import GlueExtractor
from idns.iterative.bootstrap import NameserverBootstrap
from idns.iterative.delegation import DelegationTracker
from idns.errors import (
    MaxDepthExceededError,
    ReferralError,
    DNSTimeoutError,
    ServerUnreachableError,
)

class IterativeEngine(DNSResolverProtocol):
    """
    Coordinates root, TLD, and authoritative queries to resolve a domain name.
    """
    def __init__(
        self,
        transport: DNSTransportProtocol,
        root_servers: list[dict[str, str]],
        transport_config: Optional[TransportConfig] = None,
    ) -> None:
        self.transport = transport
        self.root_servers = root_servers
        self.transport_config = transport_config
        self.bootstrap = NameserverBootstrap(
            root_servers=self.root_servers,
            transport=self.transport,
            transport_config=self.transport_config,
        )

    def resolve(
        self,
        domain_name: str,
        record_type: str = "A",
        context: Optional[ResolutionContext] = None,
    ) -> ResolverResult:
        context = context or ResolutionContext()
        qname = DNSName(domain_name)
        # Bootstrap is invoked from TLDQuery as well as directly below.  Keep
        # the request context on the helper so those nested queries contribute
        # to the same logical query count without changing old call sites.
        self.bootstrap.query_context = context
        
        root_query = RootQuery(
            root_servers=self.root_servers,
            transport=self.transport,
            transport_config=self.transport_config,
        )

        root_response, root_result = root_query.query(
            domain_name,
            record_type=record_type,
        )
        context.query_count += 1
        total_rtt = root_result.rtt_ms
        context.trace_log.append(f"root query: {domain_name} {record_type}")

        if self._is_final_answer(root_response, domain_name):
            return self._build_result(domain_name, record_type, root_response, context, total_rtt)

        labels = qname.labels
        if len(labels) < 2:
            return self._build_result(domain_name, record_type, root_response, context, total_rtt)

        tld_zone = ".".join(labels[-1:])
        tld_query = TLDQuery(
            transport=self.transport,
            transport_config=self.transport_config,
            bootstrap=self.bootstrap,
        )

        tld_response, tld_result = tld_query.query(
            root_response,
            domain_name,
            tld_zone,
            record_type=record_type,
        )
        context.query_count += 1
        total_rtt += tld_result.rtt_ms
        context.trace_log.append(f"tld query: {domain_name} {record_type}")

        if self._is_final_answer(tld_response, domain_name):
            return self._build_result(domain_name, record_type, tld_response, context, total_rtt)

        delegated_zone = ".".join(labels[-2:])
        tracker = DelegationTracker()
        current_response = tld_response
        current_zone = delegated_zone

        authoritative_query = AuthoritativeQuery(
            transport=self.transport,
            transport_config=self.transport_config,
        )

        while True:
            context.increment_depth()
            
            referral_nameservers = ReferralParser.select_nameservers(
                current_response,
                current_zone,
            )

            if not referral_nameservers:
                return self._build_result(domain_name, record_type, current_response, context, total_rtt)

            tracker.record_referral(current_zone, referral_nameservers)
            glue = GlueExtractor.extract(current_response, referral_nameservers)

            next_response: Optional[DNSMessage] = None
            progressed = False
            last_transport_error = None

            for referral_nameserver in referral_nameservers:
                server_addresses = glue.get(referral_nameserver, [])
                if not server_addresses:
                    try:
                        server_addresses = self.bootstrap.resolve(referral_nameserver)
                    except ValueError:
                        server_addresses = []

                for address in server_addresses:
                    server = ServerAddress(
                        ip=address,
                        port=53,
                        protocol="UDP",
                        name=referral_nameserver.value,
                    )
                    context.queried_servers.append(address)
                    context.trace_log.append(
                        f"authoritative query: {referral_nameserver.value} ({address})"
                    )

                    try:
                        auth_response, auth_result = authoritative_query.query(
                            server,
                            domain_name,
                            record_type=record_type,
                        )
                    except (DNSTimeoutError, ServerUnreachableError) as e:
                        # Fail over on both timeout and ordinary network
                        # reachability failures (for example connection
                        # refused/ICMP port unreachable).
                        last_transport_error = e
                        context.trace_log.append(f"timeout/failover: {address}")
                        continue

                    last_transport_error = None
                    context.query_count += 1
                    total_rtt += auth_result.rtt_ms

                    if self._is_final_answer(auth_response, domain_name):
                        return self._build_result(domain_name, record_type, auth_response, context, total_rtt)

                    referral_zone = NameserverBootstrap._select_delegated_zone(
                        auth_response,
                        qname,
                        current_zone,
                    )

                    if referral_zone is not None:
                        next_response = auth_response
                        current_zone = referral_zone
                        progressed = True
                        break

                if progressed:
                    break

            if not progressed or next_response is None:
                if last_transport_error is not None:
                    raise last_transport_error
                # No progress could be made, return best effort current response
                return self._build_result(domain_name, record_type, current_response, context, total_rtt)

            current_response = next_response

    def _is_final_answer(self, response: DNSMessage, domain_name: str) -> bool:
        """
        Determines if the response is a final answer (NOERROR with answers, NXDOMAIN, NODATA).
        """
        if response.header.rcode in (3, 2, 1, 4, 5):
            return True
        if response.answers:
            return True
        # NODATA is NOERROR (0) with no answers but has SOA
        if response.header.rcode == 0 and not response.answers and any(
            getattr(r, "record_type", "") == "SOA"
            for r in response.authorities
        ):
            return True
        return False

    def _build_result(
        self,
        domain_name: str,
        record_type: str,
        response: DNSMessage,
        context: ResolutionContext,
        total_rtt: float,
    ) -> ResolverResult:
        is_nxdomain = (response.header.rcode == 3)
        is_nodata = (
            response.header.rcode == 0
            and not response.answers
            and any(
                getattr(record, "record_type", "") == "SOA"
                for record in response.authorities
            )
        )
        return ResolverResult(
            domain_name=domain_name,
            record_type=record_type,
            answers=response.answers,
            authoritative_servers=response.authorities,
            additional_records=[
                record for record in response.additionals
                if not isinstance(record, OPTRecord)
            ],
            rcode=response.header.rcode,
            is_nxdomain=is_nxdomain,
            is_cache_hit=False,
            query_count=context.query_count,
            total_rtt_ms=total_rtt,
            cname_chain=list(context.cname_chain),
            trace_log=list(context.trace_log),
            is_nodata=is_nodata,
        )
