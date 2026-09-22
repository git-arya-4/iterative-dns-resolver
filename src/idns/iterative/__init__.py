"""
Iterative DNS Hierarchy & Referral Subsystem.

Owner: Shriyansh
Phase: Phase 4
Responsibilities:
- Root -> TLD -> Authoritative iterative step resolution
- Handling referral responses (NS records + Glue records)
- Nameserver bootstrapping and IP resolution for out-of-bailiwick referrals
- Delegation tracking without 8.8.8.8 forwarding
"""
