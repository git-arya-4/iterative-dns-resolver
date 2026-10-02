"""
Local DNS Server Subsystem.

Owner: Swastik + Arya + Avidipta
Status: Not implemented
Responsibilities:
- Socket listener accepting incoming DNS queries on port 53 / 5353
- Decoding client requests via Codec and routing through core Resolver
- Formatting and transmitting UDP DNS responses back to client
- OS resolver interface testing and browser integration
"""

from .handler import DNSRequestHandler
from .response import DNSResponseBuilder
from .udp import UDPDNSServer

__all__ = ["DNSRequestHandler", "DNSResponseBuilder", "UDPDNSServer"]
