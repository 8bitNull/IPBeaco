"""Normalize public addresses and match conservative allowlist overlaps."""

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from ipbeaco.models import Purpose, SourceError

_Network = IPv4Network | IPv6Network

# Fixed to the Python 3.12.15 ipaddress special-purpose classification. Keep
# these explicit: checking only network endpoints misses interior special space.
# On a Python minor/patch upgrade, review these against its IANA-based constants
# and run the fixed boundary samples in tests/test_addresses.py.
_SPECIAL_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
_EXCEPTIONS_V4 = ("192.0.0.9/32", "192.0.0.10/32")
_SPECIAL_V6 = (
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
    # Reserved IPv6 space is rejected even where is_global alone says True.
    "::/8",
    "100::/8",
    "200::/7",
    "400::/6",
    "800::/5",
    "1000::/4",
    "4000::/3",
    "6000::/3",
    "8000::/3",
    "a000::/3",
    "c000::/3",
    "e000::/4",
    "f000::/5",
    "f800::/6",
    "fe00::/9",
)
_EXCEPTIONS_V6 = (
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:20::/28",
    "2001:30::/28",
)


def _non_public_networks(
    special: tuple[str, ...], exceptions: tuple[str, ...]
) -> tuple[_Network, ...]:
    """Subtract public exceptions once, without enumerating any addresses."""
    result = []
    for text in special:
        pieces = [ip_network(text)]
        for exception in map(ip_network, exceptions):
            remainder = []
            for piece in pieces:
                if exception.subnet_of(piece):
                    remainder.extend(piece.address_exclude(exception))
                else:
                    remainder.append(piece)
            pieces = remainder
        result.extend(pieces)
    return tuple(result)


_NON_PUBLIC = {
    4: _non_public_networks(_SPECIAL_V4, _EXCEPTIONS_V4),
    6: _non_public_networks(_SPECIAL_V6, _EXCEPTIONS_V6),
}


def normalize_target(text: str, purpose: Purpose) -> str:
    """Return a canonical public IP/CIDR, or a SourceError with a stable code.

    Syntax errors use invalid_address/invalid_network; well-formed targets with
    excluded address space use non_public_address so collectors can filter them.
    """
    if purpose not in ("web", "network", "c2"):
        raise SourceError(f"invalid_purpose: unknown target purpose {purpose}")
    invalid = "invalid_network" if purpose == "network" else "invalid_address"
    value = text.strip()
    if "%" in value:
        raise SourceError(f"{invalid}: scoped IPv6 targets are not supported")
    if ("/" in value) != (purpose == "network"):
        raise SourceError(
            f"{invalid}: {purpose} target requires {'a CIDR' if purpose == 'network' else 'an IP'}"
        )
    try:
        parsed = ip_network(value, strict=True) if purpose == "network" else ip_address(value)
    except ValueError:
        raise SourceError(f"{invalid}: target must be a valid IP or strict CIDR") from None
    network = ip_network(str(parsed), strict=True)
    if network.version == 6 and network.network_address.ipv4_mapped is not None:
        raise SourceError("non_public_address: IPv4-mapped IPv6 targets are not supported")
    if any(network.overlaps(special) for special in _NON_PUBLIC[network.version]):
        raise SourceError("non_public_address: target contains non-public address space")
    return str(parsed)


def is_allowed(target: str, allowlist: tuple[str, ...]) -> bool:
    """Exempt a whole target if any same-family allowlist IP/CIDR overlaps."""
    candidate = ip_network(target, strict=True)
    return any(
        candidate.version == rule.version and candidate.overlaps(rule)
        for rule in map(ip_network, allowlist)
    )


def sort_key(target: str) -> tuple[int, int, int]:
    """Sort IPs and CIDRs by family, numeric network address, then prefix."""
    network = ip_network(target, strict=True)
    return network.version, int(network.network_address), network.prefixlen
