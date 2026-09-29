import pytest

from idns.errors import MaxDepthExceededError, ReferralError
from idns.iterative.delegation import DelegationTracker
from idns.model import DNSName


def test_record_referral_tracks_zone_and_nameservers():
    tracker = DelegationTracker(max_depth=3)

    zone = DNSName("example.com")
    nameservers = [
        DNSName("ns1.example.com"),
        DNSName("ns2.example.com"),
    ]

    tracker.record_referral(zone, nameservers)

    assert tracker.depth == 1
    assert zone in tracker.visited_zones
    assert nameservers[0] in tracker.visited_nameservers
    assert nameservers[1] in tracker.visited_nameservers


def test_record_referral_accepts_string_zone():
    tracker = DelegationTracker()

    tracker.record_referral(
        "example.com",
        [DNSName("ns1.example.com")],
    )

    assert DNSName("example.com") in tracker.visited_zones


def test_record_referral_rejects_empty_nameservers():
    tracker = DelegationTracker()

    with pytest.raises(ReferralError):
        tracker.record_referral(
            "example.com",
            [],
        )


def test_record_referral_rejects_repeated_zone():
    tracker = DelegationTracker()

    tracker.record_referral(
        "example.com",
        [DNSName("ns1.example.com")],
    )

    with pytest.raises(ReferralError):
        tracker.record_referral(
            "example.com",
            [DNSName("ns2.example.com")],
        )


def test_record_referral_rejects_repeated_nameservers():
    tracker = DelegationTracker()

    nameserver = DNSName("ns1.example.com")

    tracker.record_referral(
        "example.com",
        [nameserver],
    )

    with pytest.raises(ReferralError):
        tracker.record_referral(
            "other.example",
            [nameserver],
        )


def test_record_referral_allows_new_nameserver_for_new_zone():
    tracker = DelegationTracker()

    tracker.record_referral(
        "example.com",
        [DNSName("ns1.example.com")],
    )

    tracker.record_referral(
        "other.example",
        [DNSName("ns2.other.example")],
    )

    assert tracker.depth == 2


def test_record_referral_rejects_maximum_depth():
    tracker = DelegationTracker(max_depth=2)

    tracker.record_referral(
        "example.com",
        [DNSName("ns1.example.com")],
    )

    tracker.record_referral(
        "other.example",
        [DNSName("ns2.other.example")],
    )

    with pytest.raises(MaxDepthExceededError):
        tracker.record_referral(
            "third.example",
            [DNSName("ns3.third.example")],
        )


def test_tracker_reset_clears_state():
    tracker = DelegationTracker(max_depth=3)

    tracker.record_referral(
        "example.com",
        [DNSName("ns1.example.com")],
    )

    tracker.reset()

    assert tracker.depth == 0
    assert tracker.visited_zones == set()
    assert tracker.visited_nameservers == set()
    
def test_tracker_rejects_invalid_max_depth():
    with pytest.raises(ValueError):
        DelegationTracker(max_depth=0)