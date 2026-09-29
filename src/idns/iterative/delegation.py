"""Safety tracking for iterative DNS delegations."""

from idns.errors import MaxDepthExceededError, ReferralError
from idns.model import DNSName


class DelegationTracker:
    """Track iterative referrals and prevent unsafe delegation loops."""

    def __init__(self, max_depth: int = 10) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1.")

        self.max_depth = max_depth
        self.depth = 0
        self.visited_zones: set[DNSName] = set()
        self.visited_nameservers: set[DNSName] = set()

    def record_referral(
        self,
        delegated_zone: str | DNSName,
        nameservers: list[DNSName],
    ) -> None:
        """Record a referral and reject unsafe delegation patterns."""

        if self.depth >= self.max_depth:
            raise MaxDepthExceededError(
                max_depth=self.max_depth,
                current_depth=self.depth + 1,
            )

        zone = (
            delegated_zone
            if isinstance(delegated_zone, DNSName)
            else DNSName(delegated_zone)
        )

        if zone in self.visited_zones:
            raise ReferralError(
                f"Delegation loop detected for zone '{zone.value}'."
            )

        if not nameservers:
            raise ReferralError(
                f"Referral for zone '{zone.value}' contains no nameservers."
            )

        new_nameservers = [
            nameserver
            for nameserver in nameservers
            if nameserver not in self.visited_nameservers
        ]

        if not new_nameservers:
            raise ReferralError(
                f"Delegation loop detected for zone '{zone.value}': "
                "all nameservers were already visited."
            )

        self.depth += 1
        self.visited_zones.add(zone)
        self.visited_nameservers.update(new_nameservers)

    def reset(self) -> None:
        """Reset referral tracking state."""

        self.depth = 0
        self.visited_zones.clear()
        self.visited_nameservers.clear()