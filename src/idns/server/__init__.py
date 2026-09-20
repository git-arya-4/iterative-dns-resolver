"""
Local DNS Server Subsystem.

Owner: Swastik + Arya + Avidipta
Phase: Phase 6
Responsibilities:
- Socket listener accepting incoming DNS queries on port 53 / 5353
- Decoding client requests via Codec and routing through core Resolver
- Formatting and transmitting UDP DNS responses back to client
- OS resolver interface testing and browser integration
"""
