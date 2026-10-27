import time
import pytest

from idns.cache import InMemoryDNSCache
from idns.contracts.cache import CacheConfig, CacheEntry, CacheKey
from idns.extensions.dnssec import (
    canonical_name,
    canonical_rdata,
    canonical_rr,
    dnskey_key_tag,
    signed_data,
    verify_signature,
    validate_message,
)
from idns.extensions.edns0 import (
    CLIENT_SUBNET,
    COOKIE,
    EDNSConfig,
    make_client_subnet,
    make_cookie,
    make_extended_error,
    make_opt_record,
    parse_client_subnet,
    parse_cookie,
    parse_extended_error,
)
from idns.model import (
    ARecord,
    DNSHeader,
    DNSKEYRecord,
    DNSMessage,
    DNSName,
    EDNSOption,
    RRSIGRecord,
    AAAARecord,
    CNAMERecord,
    MXRecord,
    NSRecord,
    SOARecord,
    TXTRecord,
)
from idns.wire import DNSMessageDecoder, DNSMessageEncoder


def test_edns_options_round_trip_and_codecs():
    cookie = make_cookie(b"12345678", b"server")
    subnet = make_client_subnet("192.0.2.0/24")
    ede = make_extended_error(15, "blocked")
    opt = make_opt_record(EDNSConfig(dnssec_ok=True, options=(cookie, subnet, ede)))
    packet = DNSMessageEncoder.encode(DNSMessage(DNSHeader(1), additionals=[opt]))
    decoded = DNSMessageDecoder.decode(packet).additionals[0]

    assert decoded.dnssec_ok
    assert parse_cookie(next(option for option in decoded.options if option.code == COOKIE)) == (
        b"12345678", b"server"
    )
    assert parse_client_subnet(next(option for option in decoded.options if option.code == CLIENT_SUBNET))[2].with_prefixlen == "192.0.2.0/24"
    assert parse_extended_error(ede) == (15, "blocked")


def test_near_expiry_prefetch_is_best_effort_and_configurable():
    now = [100.0]
    cache = InMemoryDNSCache(
        CacheConfig(prefetch_enabled=True, prefetch_threshold_seconds=10),
        clock=lambda: now[0],
    )
    key = CacheKey.from_query("example.com", "A")
    entry = CacheEntry.create_positive(
        key,
        [ARecord(DNSName("example.com"), "192.0.2.1", 20)],
        20,
        creation_timestamp=90.0,
    )
    refreshed = CacheEntry.create_positive(
        key,
        [ARecord(DNSName("example.com"), "192.0.2.2", 300)],
        300,
        creation_timestamp=100.0,
    )
    seen = []
    cache.set_prefetch_callback(lambda callback_key, old: (seen.append(old), cache.put(callback_key, refreshed)))
    cache.put(key, entry)

    assert cache.get(key) is entry
    assert seen == [entry]
    assert cache.get(key).records[0].address == "192.0.2.2"


def test_dnssec_wire_records_decode_and_unsigned_messages_are_not_secure():
    key = DNSKEYRecord(DNSName("example.com"), 257, 3, 8, b"\x03\x01\x00\x01\x01", 300)
    signature = RRSIGRecord(
        DNSName("example.com"), "A", 8, 2, 300, 0xFFFFFFFF, 0,
        dnskey_key_tag(key), DNSName("example.com"), b"\x00", 300,
    )
    message = DNSMessage(
        DNSHeader(1),
        answers=[ARecord(DNSName("example.com"), "192.0.2.1", 300), signature],
        additionals=[key],
    )
    decoded = DNSMessageDecoder.decode(DNSMessageEncoder.encode(message))
    validation = validate_message(decoded, now=int(time.time()))

    assert decoded.answers[1].record_type == "RRSIG"
    assert validation.bogus
    assert not validation.secure
    assert validate_message(DNSMessage(DNSHeader(2))).unchecked


def test_dnssec_canonical_data_supports_project_record_types():
    owner = DNSName("WWW.Example.COM")
    records = [
        ARecord(owner, "192.0.2.1", 60),
        AAAARecord(owner, "2001:db8::1", 60),
        NSRecord(owner, DNSName("ns.example.com"), 60),
        CNAMERecord(owner, DNSName("target.example.com"), 60),
        MXRecord(owner, 10, DNSName("mail.example.com"), 60),
        TXTRecord(owner, ("hello", "world"), 60),
        SOARecord(owner, DNSName("ns.example.com"), DNSName("hostmaster.example.com"), 1, 2, 3, 4, 5, 60),
    ]
    assert canonical_name(owner) == b"\x03www\x07example\x03com\x00"
    for record in records:
        encoded = canonical_rdata(record)
        assert encoded
        assert canonical_rr(record, 60).endswith(encoded)

    key = DNSKEYRecord(owner, 257, 3, 8, b"\x03\x01\x00\x01\x01", 60)
    signature = RRSIGRecord(owner, "A", 8, 1, 60, 0xFFFFFFFF, 0, dnskey_key_tag(key), owner, b"\x00", 60)
    assert canonical_rdata(key)
    assert signed_data([records[0]], signature)
    assert not verify_signature([records[0]], signature, key, now=1)


def test_edns_validation_rejects_malformed_options():
    with pytest.raises(ValueError):
        EDNSConfig(udp_payload_size=100)
    with pytest.raises(ValueError):
        make_cookie(b"short")
    with pytest.raises(ValueError):
        parse_cookie(EDNSOption(COOKIE, b"short"))
    with pytest.raises(ValueError):
        parse_client_subnet(EDNSOption(CLIENT_SUBNET, b"\x00"))
    with pytest.raises(ValueError):
        parse_extended_error(EDNSOption(15, b"\x00"))
