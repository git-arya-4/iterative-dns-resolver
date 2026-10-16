from idns.contracts.resolver import ResolverResult
from idns.model import DNSHeader, DNSMessage, DNSName, OPTRecord


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
        request_opt = next(
            (record for record in request.additionals if isinstance(record, OPTRecord)),
            None,
        )
        response_additionals = [
            record for record in result.additional_records
            if not isinstance(record, OPTRecord)
        ]
        # This resolver implements EDNS version 0 only.  Echo a deliberately
        # constructed OPT response and retain only the DO flag we understand.
        if request_opt is not None and request_opt.version == 0:
            response_additionals.append(
                OPTRecord(
                    name=DNSName("."),
                    udp_payload_size=request_opt.udp_payload_size,
                    flags=request_opt.flags & 0x8000,
                )
            )
        response = DNSMessage(
            header=header,
            questions=list(request.questions),
            answers=list(result.answers),
            authorities=list(result.authoritative_servers),
            additionals=response_additionals,
        )
        response.update_counts()
        return response

    @staticmethod
    def error(request_or_transaction_id, rcode: int, question=None) -> DNSMessage:
        if isinstance(request_or_transaction_id, DNSMessage):
            request = request_or_transaction_id
            transaction_id = request.header.transaction_id
            question = request.questions[0] if request.questions else question
            opcode = request.header.opcode
            rd = request.header.rd
        else:
            transaction_id = request_or_transaction_id
            opcode = 0
            rd = 0
        response = DNSMessage(
            header=DNSHeader(transaction_id=transaction_id, qr=1, opcode=opcode, rd=rd, ra=1, rcode=rcode),
            questions=[question] if question else [],
        )
        response.update_counts()
        return response
