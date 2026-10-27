"""EDNS(0) helpers and commonly used option codecs.

The wire layer already preserves unknown options.  This module adds the
policy/option layer needed to use EDNS safely: payload-size negotiation, DO,
NSID, COOKIE, ECS, PADDING, and Extended DNS Errors (RFC 8914).
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from idns.model import DNSName, EDNSOption, OPTRecord


NSID = 3
CLIENT_SUBNET = 8
COOKIE = 10
PADDING = 12
EXTENDED_DNS_ERROR = 15


@dataclass(frozen=True)
class EDNSConfig:
    """EDNS request parameters used by iterative query builders."""

    udp_payload_size: int = 1232
    dnssec_ok: bool = False
    options: tuple[EDNSOption, ...] = ()

    def __post_init__(self) -> None:
        if not 512 <= self.udp_payload_size <= 65535:
            raise ValueError("EDNS UDP payload size must be between 512 and 65535")


def make_opt_record(config: EDNSConfig) -> OPTRecord:
    """Build an OPT record from validated EDNS request settings."""
    return OPTRecord(
        name=DNSName("."),
        udp_payload_size=config.udp_payload_size,
        flags=0x8000 if config.dnssec_ok else 0,
        options=tuple(config.options),
    )


def opt_from_transport_config(config: object | None) -> OPTRecord | None:
    """Return an OPT record when transport EDNS is enabled."""
    if config is None or not getattr(config, "edns_enabled", False):
        return None
    return make_opt_record(
        EDNSConfig(
            udp_payload_size=getattr(config, "edns_udp_payload_size", 1232),
            dnssec_ok=getattr(config, "edns_dnssec_ok", False),
            options=tuple(getattr(config, "edns_options", ())),
        )
    )


def get_opt(message) -> OPTRecord | None:
    return next((record for record in message.additionals if isinstance(record, OPTRecord)), None)


def get_options(opt: OPTRecord, code: int) -> tuple[EDNSOption, ...]:
    return tuple(option for option in opt.options if option.code == code)


def make_nsid(value: bytes = b"") -> EDNSOption:
    return EDNSOption(NSID, value)


def make_cookie(client_cookie: bytes, server_cookie: bytes = b"") -> EDNSOption:
    if not 8 <= len(client_cookie) <= 32:
        raise ValueError("EDNS COOKIE client cookie must be 8 to 32 bytes")
    if len(server_cookie) > 32:
        raise ValueError("EDNS COOKIE server cookie must be at most 32 bytes")
    return EDNSOption(COOKIE, client_cookie + server_cookie)


def parse_cookie(option: EDNSOption) -> tuple[bytes, bytes]:
    if option.code != COOKIE or not 8 <= len(option.data) <= 64:
        raise ValueError("invalid EDNS COOKIE option")
    return option.data[:8], option.data[8:]


def make_client_subnet(network: str, source_prefix: int | None = None) -> EDNSOption:
    address = ipaddress.ip_network(network, strict=False)
    prefix = address.prefixlen if source_prefix is None else source_prefix
    max_prefix = address.max_prefixlen
    if not 0 <= prefix <= max_prefix:
        raise ValueError("invalid ECS source prefix")
    family = 1 if address.version == 4 else 2
    significant = (prefix + 7) // 8
    packed = bytearray(address.network_address.packed[:significant])
    if packed and prefix % 8:
        packed[-1] &= 0xFF << (8 - prefix % 8)
    return EDNSOption(CLIENT_SUBNET, struct.pack("!HBB", family, prefix, 0) + bytes(packed))


def parse_client_subnet(option: EDNSOption) -> tuple[int, int, ipaddress._BaseNetwork]:
    if option.code != CLIENT_SUBNET or len(option.data) < 4:
        raise ValueError("invalid EDNS Client Subnet option")
    family, source_prefix, scope_prefix = struct.unpack("!HBB", option.data[:4])
    if family not in (1, 2):
        raise ValueError("unsupported EDNS Client Subnet address family")
    bits = 32 if family == 1 else 128
    size = (source_prefix + 7) // 8
    if source_prefix > bits or len(option.data) != 4 + size:
        raise ValueError("invalid EDNS Client Subnet prefix")
    raw = option.data[4:] + b"\x00" * ((bits // 8) - size)
    address = ipaddress.ip_address(raw)
    return source_prefix, scope_prefix, ipaddress.ip_network(f"{address}/{source_prefix}", strict=False)


def make_padding(length: int) -> EDNSOption:
    if length < 0 or length > 65535:
        raise ValueError("EDNS padding length is out of range")
    return EDNSOption(PADDING, b"\x00" * length)


def make_extended_error(info_code: int, text: str = "") -> EDNSOption:
    if not 0 <= info_code <= 65535:
        raise ValueError("extended DNS error code is out of range")
    return EDNSOption(EXTENDED_DNS_ERROR, struct.pack("!H", info_code) + text.encode("utf-8"))


def parse_extended_error(option: EDNSOption) -> tuple[int, str]:
    if option.code != EXTENDED_DNS_ERROR or len(option.data) < 2:
        raise ValueError("invalid Extended DNS Error option")
    return struct.unpack("!H", option.data[:2])[0], option.data[2:].decode("utf-8")


__all__ = [
    "EDNSConfig", "make_opt_record", "opt_from_transport_config", "get_opt",
    "get_options", "make_nsid", "make_cookie", "parse_cookie",
    "make_client_subnet", "parse_client_subnet", "make_padding",
    "make_extended_error", "parse_extended_error", "NSID", "CLIENT_SUBNET",
    "COOKIE", "PADDING", "EXTENDED_DNS_ERROR",
]
