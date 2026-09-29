"""DNS referral parsing for iterative resolution."""

from idns.model import DNSMessage, DNSName, NSRecord


class ReferralParser:
    """Parse authoritative NS referrals from DNS responses."""

    @staticmethod
    def select_nameservers(
        response: DNSMessage,
        delegated_zone: str,
    ) -> list[DNSName]:
        """Return NS nameservers for the delegated zone."""

        zone = DNSName(delegated_zone)

        nameservers: list[DNSName] = []

        for record in response.authorities:
            if not isinstance(record, NSRecord):
                continue

            if record.name == zone:
                nameservers.append(record.nameserver)

        return nameservers