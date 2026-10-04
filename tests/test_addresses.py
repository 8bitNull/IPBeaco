"""Offline boundaries for public targets and conservative allowlist overlap."""

import pytest

from ipbeaco.addresses import is_allowed, normalize_target, sort_key
from ipbeaco.models import SourceError


@pytest.mark.parametrize(
    ("text", "purpose", "expected"),
    [
        (" 8.8.8.8 \n", "web", "8.8.8.8"),
        ("1.1.1.1", "c2", "1.1.1.1"),
        ("2606:4700:4700:0:0:0:0:1111", "web", "2606:4700:4700::1111"),
        (" 2606:4700:ABCD::/48 ", "network", "2606:4700:abcd::/48"),
        ("8.8.8.0/24", "network", "8.8.8.0/24"),
        ("8.8.8.8/32", "network", "8.8.8.8/32"),
        ("2606:4700::1/128", "network", "2606:4700::1/128"),
        ("192.0.0.9", "web", "192.0.0.9"),
        ("192.0.0.10/32", "network", "192.0.0.10/32"),
        ("2001:3::/32", "network", "2001:3::/32"),
        ("2001:20::/28", "network", "2001:20::/28"),
    ],
)
def test_normalizes_public_targets(text, purpose, expected):
    assert normalize_target(text, purpose) == expected


@pytest.mark.parametrize(
    "text",
    [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "192.0.0.8",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "::ffff:10.0.0.1",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "4000::1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ],
)
def test_rejects_non_public_single_addresses(text):
    with pytest.raises(SourceError):
        normalize_target(text, "web")


@pytest.mark.parametrize(
    "text",
    [
        "8.0.0.0/6",  # Both endpoints public; private 10/8 lies inside.
        "192.0.0.0/8",  # Multiple distinct special ranges inside one supernet.
        "2000::/3",  # Public endpoints contain documentation and transition space.
        "2001:db8::/32",
        "3fff::/20",
        "224.0.0.0/4",
        "100.64.0.0/10",
        "::ffff:8.8.8.8/128",
        "192.0.0.8/30",
        "2001::/23",
        "::/0",
        "0.0.0.0/0",
    ],
)
def test_rejects_entire_network_if_any_address_is_non_public(text):
    with pytest.raises(SourceError):
        normalize_target(text, "network")


@pytest.mark.parametrize(
    ("text", "purpose"),
    [
        ("8.8.8.8/24", "network"),
        ("2606:4700::1/64", "network"),
        ("8.8.8.0/24", "web"),
        ("8.8.8.8/32", "c2"),
        ("8.8.8.8", "network"),
        ("", "web"),
        ("example.com", "web"),
        ("999.1.1.1", "web"),
        ("8.8.8.8:443", "web"),
        ("2606:4700::1%eth0", "web"),
        ("8.8.8.8", "unknown"),
    ],
)
def test_rejects_invalid_syntax_or_purpose(text, purpose):
    with pytest.raises(SourceError):
        normalize_target(text, purpose)


@pytest.mark.parametrize(
    ("text", "purpose", "code"),
    [
        ("example.com", "web", "invalid_address"),
        ("8.8.8.8/32", "c2", "invalid_address"),
        ("2606:4700::1%eth0", "web", "invalid_address"),
        ("8.8.8.8", "network", "invalid_network"),
        ("8.8.8.1/24", "network", "invalid_network"),
        ("2606:4700::%eth0/64", "network", "invalid_network"),
        ("10.0.0.1", "web", "non_public_address"),
        ("8.0.0.0/6", "network", "non_public_address"),
        ("::ffff:8.8.8.8", "web", "non_public_address"),
        ("8.8.8.8", "unknown", "invalid_purpose"),
    ],
)
def test_source_error_codes_distinguish_invalid_syntax_from_non_public_targets(text, purpose, code):
    with pytest.raises(SourceError, match=f"^{code}:"):
        normalize_target(text, purpose)


@pytest.mark.parametrize(
    ("target", "allowlist", "expected"),
    [
        ("8.8.8.0/24", ("8.8.8.8",), True),
        ("8.8.4.0/24", ("8.8.8.8",), False),
        ("8.8.8.8", ("8.8.8.0/24",), True),
        ("8.8.8.0/24", ("8.8.8.128/25",), True),
        ("8.8.8.8", ("8.8.8.8",), True),
        ("8.8.8.8", (), False),
        ("2606:4700::/32", ("2606:4700::1111",), True),
        ("2606:4700::1111", ("2606:4700::/32",), True),
        ("2606:4700::1111", ("8.8.8.8",), False),
        ("8.8.8.8", ("2606:4700::/32",), False),
        ("8.8.4.0/24", ("1.1.1.1", "8.8.4.4"), True),
    ],
)
def test_allowlist_matches_any_overlap_within_same_address_family(target, allowlist, expected):
    assert is_allowed(target, allowlist) is expected


def test_sort_key_orders_family_address_and_prefix_numerically():
    targets = ["2606:4700::1", "8.8.8.8", "8.8.8.0/25", "1.1.1.1", "8.8.8.0/24"]
    assert sorted(targets, key=sort_key) == [
        "1.1.1.1",
        "8.8.8.0/24",
        "8.8.8.0/25",
        "8.8.8.8",
        "2606:4700::1",
    ]
    assert sort_key("8.8.8.8") == (4, 134744072, 32)
