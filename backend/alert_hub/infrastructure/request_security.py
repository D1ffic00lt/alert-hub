from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from starlette.requests import Request

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_FORWARDED_FOR = re.compile(r"(?:^|;)\s*for=(\"[^\"]+\"|[^;]+)", re.IGNORECASE)


def normalize_cidrs(values: Iterable[object]) -> list[str]:
    """Return canonical, de-duplicated IP networks or raise for an invalid value."""

    normalized: list[str] = []
    for raw in values:
        candidate = str(raw).strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {candidate}") from exc
        canonical = str(network)
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized


def parse_cidr_setting(value: object) -> object:
    """Pydantic before-validator helper for JSON or comma-separated CIDR settings."""

    if isinstance(value, str):
        import json

        if value.lstrip().startswith("["):
            value = json.loads(value)
        else:
            value = [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return normalize_cidrs(value)
    return value


def address_in_cidrs(address: str | None, cidrs: Iterable[str]) -> bool:
    if address is None:
        return False
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return False
    for raw_network in cidrs:
        try:
            network = ipaddress.ip_network(raw_network, strict=False)
        except ValueError:
            continue
        if parsed_address.version == network.version and parsed_address in network:
            return True
    return False


def _parse_forwarded_address(value: str) -> IPAddress | None:
    candidate = value.strip().strip('"')
    if not candidate or candidate.lower() == "unknown" or candidate.startswith("_"):
        return None
    if candidate.startswith("["):
        end = candidate.find("]")
        if end == -1:
            return None
        candidate = candidate[1:end]
    else:
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:
            # RFC 7239 permits an IPv4 address followed by a port.
            host, separator, port = candidate.rpartition(":")
            if not separator or not port.isdigit():
                return None
            candidate = host
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _forwarded_chain(request: Request) -> list[IPAddress] | None:
    x_forwarded_for = request.headers.getlist("x-forwarded-for")
    if x_forwarded_for:
        xff_addresses = [
            _parse_forwarded_address(item)
            for header in x_forwarded_for
            for item in header.split(",")
        ]
        if not xff_addresses or any(address is None for address in xff_addresses):
            return None
        return [address for address in xff_addresses if address is not None]

    forwarded = request.headers.getlist("forwarded")
    if forwarded:
        forwarded_addresses: list[IPAddress] = []
        for header in forwarded:
            for element in header.split(","):
                match = _FORWARDED_FOR.search(element)
                if match is None:
                    return None
                address = _parse_forwarded_address(match.group(1))
                if address is None:
                    return None
                forwarded_addresses.append(address)
        return forwarded_addresses or None

    real_ip = request.headers.getlist("x-real-ip")
    if real_ip:
        if len(real_ip) != 1:
            return None
        address = _parse_forwarded_address(real_ip[0])
        if address is None:
            return None
        return [address]
    return []


def resolve_client_ip(request: Request, trusted_proxy_cidrs: Iterable[str]) -> str | None:
    """Resolve a client IP without trusting headers from an untrusted immediate peer.

    The forwarded chain is walked from right to left. Every trusted proxy is skipped;
    the first untrusted hop is the effective client. Invalid headers fail closed to the
    immediate peer rather than accepting a different forwarding header.
    """

    peer_host = request.client.host if request.client is not None else None
    try:
        peer = ipaddress.ip_address(peer_host) if peer_host else None
    except ValueError:
        return None
    if peer is None:
        return None
    networks = tuple(ipaddress.ip_network(item, strict=False) for item in trusted_proxy_cidrs)
    peer_is_trusted = any(
        peer.version == network.version and peer in network for network in networks
    )
    if not peer_is_trusted:
        return str(peer)

    forwarded = _forwarded_chain(request)
    if forwarded is None or not forwarded:
        return str(peer)
    chain = [*forwarded, peer]
    for address in reversed(chain):
        trusted = any(
            address.version == network.version and address in network for network in networks
        )
        if not trusted:
            return str(address)
    return str(chain[0])
