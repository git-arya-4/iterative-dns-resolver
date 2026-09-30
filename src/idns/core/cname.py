"""
CNAME chain processing and safety limits (Tasks 5.4 and 5.5).
"""

from typing import Callable, Any
from idns.contracts.resolver import ResolutionContext, ResolverResult
from idns.model import CNAMERecord

ResolveCallback = Callable[[str, str, ResolutionContext], ResolverResult]

class CNAMEChainProcessor:
    """
    Processes CNAME chains, handling intra-response alias chasing
    and inter-query recursive chasing, while enforcing strict 
    loop protection and depth limits.
    """
    
    def __init__(self, resolver_callback: ResolveCallback):
        self.resolver_callback = resolver_callback

    def process(
        self,
        domain_name: str,
        record_type: str,
        result: ResolverResult,
        context: ResolutionContext,
    ) -> ResolverResult:
        """
        Process CNAME aliases in the result. If a CNAME is found and the 
        original query was not explicitly for CNAME, follow the chain.
        """
        # If the explicit query was CNAME, we do not follow aliases.
        if record_type == "CNAME":
            return result

        current_name = domain_name.strip().lower().rstrip('.')
        current_result = result

        while True:
            # Look for a CNAME record for the current_name in the current result answers
            cname_record = None
            for answer in current_result.answers:
                if isinstance(answer, CNAMERecord) and answer.name.value.lower() == current_name:
                    cname_record = answer
                    break
            
            if not cname_record:
                # No CNAME for the current name, we are done
                break

            target = cname_record.canonical_name.value.lower()
            
            # Record the transition: this handles cycle detection natively
            context.record_cname(current_name)
            # Depth must be incremented for EVERY CNAME transition, even intra-response
            context.increment_depth()

            current_name = target
            
            # Check if the target is already resolved in the SAME response
            # e.g., a CNAME b, b A 1.2.3.4
            target_answered = False
            for answer in current_result.answers:
                if answer.name.value.lower() == target:
                    target_answered = True
                    break
            
            if target_answered:
                # The target is already answered in the same response, loop again to see if 
                # there's ANOTHER CNAME or if we are done. We don't need a new network query.
                continue
                
            # If the target is NOT answered in the same response, we must issue a new query
            # via the callback to resolve the target.
            next_result = self.resolver_callback(target, record_type, context)
            print(f"DEBUG: resolving {target} returned {len(next_result.answers)} answers: {next_result.answers}")
            
            # Merge answers from the new query into the current result
            current_result.answers.extend(next_result.answers)
            current_result.authoritative_servers.extend(next_result.authoritative_servers)
            current_result.additional_records.extend(next_result.additional_records)
            current_result.query_count = next_result.query_count
            current_result.total_rtt_ms += next_result.total_rtt_ms
            current_result.rcode = next_result.rcode
            current_result.is_nxdomain = next_result.is_nxdomain
            
            # In a multi-hop scenario where the next result is a miss but target is NXDOMAIN
            if current_result.is_nxdomain:
                break

        # Final record keeping
        current_result.cname_chain = list(context.cname_chain)
        return current_result
