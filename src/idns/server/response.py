from idns.contracts.resolver import ResolverResult
from idns.model import DNSHeader, DNSMessage


class DNSResponseBuilder:
    @staticmethod
    def build(request: DNSMessage, result: ResolverResult) -> DNSMessage:
        header = DNSHeader(
            transaction_id=request.header.transaction_id,
            qr=1,
            opcode=request.header.opcode,
            aa=0,
            rd=request.header.rd,
            ra=1,
            rcode=result.rcode,
        )
        response = DNSMessage(
            header=header,
            questions=list(request.questions),
            answers=list(result.answers),
            authorities=list(result.authoritative_servers),
            additionals=list(result.additional_records),
        )
        response.update_counts()
        return response

    @staticmethod
    def error(transaction_id: int, rcode: int, question=None) -> DNSMessage:
        response = DNSMessage(
            header=DNSHeader(transaction_id=transaction_id, qr=1, ra=1, rcode=rcode),
            questions=[question] if question else [],
        )
        response.update_counts()
        return response
