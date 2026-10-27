"""Small, dependency-free DNSSEC validator for RSA DNSKEY/RRSIG records.

The validator deliberately does not use a general-purpose crypto package.
It implements the DNSSEC RSA algorithms defined by RFC 4034/5702 using the
Python standard library's big-integer arithmetic and hashlib.  Unsupported
algorithms are reported as unchecked instead of being treated as secure.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
import time
from dataclasses import dataclass

from idns.model import (
    ARecord,
    AAAARecord,
    CNAMERecord,
    DNSKEYRecord,
    DSRecord,
    DNSName,
    MXRecord,
    NSRecord,
    RRSIGRecord,
    SOARecord,
    TXTRecord,
)


TYPE_CODES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
    "AAAA": 28, "DS": 43, "RRSIG": 46, "DNSKEY": 48,
}
CLASS_IN = 1
RSA_SHA1 = {5, 7}
RSA_SHA256 = {8}
RSA_SHA512 = {10}


class DNSSECValidationError(ValueError):
    """Raised for malformed DNSSEC data supplied to the validator."""


@dataclass(frozen=True)
class DNSSECValidationResult:
    secure: bool
    bogus: bool
    unchecked: bool
    validated_rrsets: int
    errors: tuple[str, ...] = ()


def canonical_name(name: DNSName | str) -> bytes:
    dns_name = name if isinstance(name, DNSName) else DNSName(name)
    result = bytearray()
    for label in dns_name.labels:
        encoded = label.lower().encode("ascii")
        if len(encoded) > 63:
            raise DNSSECValidationError("DNS label is too long")
        result.append(len(encoded))
        result.extend(encoded)
    result.append(0)
    return bytes(result)


def dnskey_rdata(key: DNSKEYRecord) -> bytes:
    return struct.pack("!HBB", key.flags, key.protocol, key.algorithm) + key.public_key


def dnskey_key_tag(key: DNSKEYRecord) -> int:
    data = dnskey_rdata(key)
    accumulator = 0
    for index, value in enumerate(data):
        accumulator += value << 8 if index % 2 == 0 else value
    accumulator += (accumulator >> 16) & 0xFFFF
    return accumulator & 0xFFFF


def _name_for_signature(record: object, labels: int) -> bytes:
    name = getattr(record, "name", None)
    if not isinstance(name, DNSName):
        raise DNSSECValidationError("record has no DNS owner name")
    if labels >= len(name.labels):
        return canonical_name(name)
    if labels < 1:
        raise DNSSECValidationError("invalid RRSIG label count")
    return canonical_name(DNSName("*." + ".".join(name.labels[-labels:])))


def _name_rdata(name: DNSName) -> bytes:
    return canonical_name(name)


def canonical_rdata(record: object) -> bytes:
    if isinstance(record, ARecord):
        return ipaddress.IPv4Address(record.address).packed
    if isinstance(record, AAAARecord):
        return ipaddress.IPv6Address(record.address).packed
    if isinstance(record, NSRecord):
        return _name_rdata(record.nameserver)
    if isinstance(record, CNAMERecord):
        return _name_rdata(record.canonical_name)
    if isinstance(record, MXRecord):
        return struct.pack("!H", record.preference) + _name_rdata(record.exchange)
    if isinstance(record, TXTRecord):
        return b"".join(bytes([len(part.encode("utf-8"))]) + part.encode("utf-8") for part in record.text)
    if isinstance(record, SOARecord):
        return (
            _name_rdata(record.mname) + _name_rdata(record.rname)
            + struct.pack("!IIIII", record.serial, record.refresh, record.retry,
                          record.expire, record.minimum)
        )
    if isinstance(record, DNSKEYRecord):
        return dnskey_rdata(record)
    if isinstance(record, DSRecord):
        return struct.pack("!HBB", record.key_tag, record.algorithm, record.digest_type) + record.digest
    raise DNSSECValidationError(f"unsupported DNSSEC canonical record: {type(record).__name__}")


def canonical_rr(record: object, ttl: int, labels: int | None = None) -> bytes:
    record_type = getattr(record, "record_type", "").upper()
    if record_type not in TYPE_CODES:
        raise DNSSECValidationError(f"unsupported RR type {record_type}")
    owner = _name_for_signature(record, labels if labels is not None else len(record.name.labels))
    rdata = canonical_rdata(record)
    return owner + struct.pack("!HHIH", TYPE_CODES[record_type], CLASS_IN, ttl, len(rdata)) + rdata


def _signature_header(signature: RRSIGRecord) -> bytes:
    covered = TYPE_CODES.get(signature.type_covered.upper())
    if covered is None:
        raise DNSSECValidationError(f"unsupported covered type {signature.type_covered}")
    return struct.pack(
        "!HBBIIIH", covered, signature.algorithm, signature.labels,
        signature.original_ttl, signature.signature_expiration,
        signature.signature_inception, signature.key_tag,
    ) + canonical_name(signature.signer_name)


def signed_data(rrset: list[object], signature: RRSIGRecord) -> bytes:
    if not rrset:
        raise DNSSECValidationError("cannot validate an empty RRset")
    records = sorted(
        (canonical_rr(record, signature.original_ttl, signature.labels) for record in rrset),
    )
    return _signature_header(signature) + b"".join(records)


def _rsa_components(key: DNSKEYRecord) -> tuple[int, int]:
    data = key.public_key
    if not data:
        raise DNSSECValidationError("DNSKEY public key is empty")
    exponent_length = data[0]
    offset = 1
    if exponent_length == 0:
        if len(data) < 3:
            raise DNSSECValidationError("truncated DNSKEY exponent length")
        exponent_length = int.from_bytes(data[1:3], "big")
        offset = 3
    if exponent_length == 0 or len(data) <= offset + exponent_length:
        raise DNSSECValidationError("invalid DNSKEY exponent")
    exponent = int.from_bytes(data[offset:offset + exponent_length], "big")
    modulus = int.from_bytes(data[offset + exponent_length:], "big")
    if exponent <= 1 or modulus <= 0:
        raise DNSSECValidationError("invalid RSA DNSKEY components")
    return exponent, modulus


def _digest(algorithm: int, data: bytes) -> tuple[bytes, bytes]:
    if algorithm in RSA_SHA1:
        return hashlib.sha1(data).digest(), bytes.fromhex("3021300906052b0e03021a05000414")
    if algorithm in RSA_SHA256:
        return hashlib.sha256(data).digest(), bytes.fromhex("3031300d060960864801650304020105000420")
    if algorithm in RSA_SHA512:
        return hashlib.sha512(data).digest(), bytes.fromhex("3051300d060960864801650304020305000440")
    raise DNSSECValidationError(f"unsupported DNSSEC RSA algorithm {algorithm}")


def verify_signature(rrset: list[object], signature: RRSIGRecord, key: DNSKEYRecord, now: int | None = None) -> bool:
    if key.name != signature.signer_name or key.algorithm != signature.algorithm:
        return False
    if dnskey_key_tag(key) != signature.key_tag:
        return False
    if signature.algorithm not in RSA_SHA1 | RSA_SHA256 | RSA_SHA512:
        raise DNSSECValidationError(f"unsupported DNSSEC algorithm {signature.algorithm}")
    current = int(time.time()) if now is None else int(now)
    current &= 0xFFFFFFFF
    # DNSSEC timestamps are unsigned serial numbers; this handles the normal
    # 32-bit wrap-around window while remaining simple for ordinary dates.
    before_expiration = ((signature.signature_expiration - current) & 0xFFFFFFFF) < 0x80000000
    after_inception = ((current - signature.signature_inception) & 0xFFFFFFFF) < 0x80000000
    if not before_expiration or not after_inception:
        return False
    digest, prefix = _digest(signature.algorithm, signed_data(rrset, signature))
    exponent, modulus = _rsa_components(key)
    size = (modulus.bit_length() + 7) // 8
    if len(signature.signature) != size:
        return False
    encoded = pow(int.from_bytes(signature.signature, "big"), exponent, modulus).to_bytes(size, "big")
    expected = b"\x00\x01" + b"\xff" * (size - len(prefix) - len(digest) - 3) + b"\x00" + prefix + digest
    return encoded == expected


def verify_rrset(rrset: list[object], signatures: list[RRSIGRecord], keys: list[DNSKEYRecord], now: int | None = None) -> bool:
    if not rrset or not signatures:
        return False
    covered_type = getattr(rrset[0], "record_type", "").upper()
    for signature in signatures:
        if signature.type_covered.upper() != covered_type:
            continue
        for key in keys:
            if verify_signature(rrset, signature, key, now):
                return True
    return False


def verify_ds(ds: DSRecord, key: DNSKEYRecord) -> bool:
    """Verify that a DS digest identifies a DNSKEY at the owner name."""
    if ds.key_tag != dnskey_key_tag(key) or ds.algorithm != key.algorithm:
        return False
    owner_and_key = canonical_name(key.name) + dnskey_rdata(key)
    if ds.digest_type == 1:
        digest = hashlib.sha1(owner_and_key).digest()
    elif ds.digest_type == 2:
        digest = hashlib.sha256(owner_and_key).digest()
    elif ds.digest_type == 4:
        digest = hashlib.sha384(owner_and_key).digest()
    else:
        raise DNSSECValidationError(f"unsupported DS digest type {ds.digest_type}")
    return digest == ds.digest


def validate_message(message, now: int | None = None) -> DNSSECValidationResult:
    """Validate every signed RRset for which DNSKEYs are present in a message."""
    records = list(message.answers) + list(message.authorities) + list(message.additionals)
    signatures = [record for record in records if isinstance(record, RRSIGRecord)]
    keys = [record for record in records if isinstance(record, DNSKEYRecord)]
    if not signatures:
        return DNSSECValidationResult(False, False, True, 0, ("message contains no RRSIG records",))
    errors: list[str] = []
    validated = 0
    for signature in signatures:
        rrset = [
            record for record in records
            if getattr(record, "record_type", "").upper() == signature.type_covered.upper()
            and getattr(record, "name", None) == signature.name
        ]
        matching_keys = [key for key in keys if key.name == signature.signer_name]
        if not matching_keys:
            errors.append(f"no DNSKEY for signer {signature.signer_name.value}")
            continue
        try:
            if verify_rrset(rrset, [signature], matching_keys, now):
                validated += 1
            else:
                errors.append(f"signature verification failed for {signature.name.value}")
        except DNSSECValidationError as error:
            errors.append(str(error))
    return DNSSECValidationResult(
        secure=validated == len(signatures),
        bogus=bool(errors),
        unchecked=False,
        validated_rrsets=validated,
        errors=tuple(errors),
    )


__all__ = [
    "DNSSECValidationError", "DNSSECValidationResult", "canonical_name",
    "canonical_rdata", "canonical_rr", "dnskey_key_tag", "signed_data",
    "verify_signature", "verify_rrset", "verify_ds", "validate_message",
]
