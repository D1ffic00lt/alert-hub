from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from urllib.parse import SplitResult, urlsplit, urlunsplit

Resolver = Callable[..., Iterable[tuple[int, int, int, str, tuple[object, ...]]]]
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class UnsafeURL(ValueError):
    pass


def _require_public_ip(value: str) -> None:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise UnsafeURL("webhook resolved to an invalid address") from exc
    if not address.is_global:
        raise UnsafeURL(
            "webhook destination must not be private, loopback, link-local, or reserved"
        )


def validate_webhook_url(
    value: str,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
    require_resolution: bool = False,
    resolver: Resolver = socket.getaddrinfo,
) -> str:
    if len(value) > 2_048:
        raise UnsafeURL("webhook URL is too long")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("webhook URL is invalid") from exc
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise UnsafeURL("webhook URL must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise UnsafeURL("webhook URL must contain a hostname and no embedded credentials")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
        raise UnsafeURL("local webhook hostnames are not allowed")
    if not allow_private:
        literal_address = False
        try:
            _require_public_ip(hostname)
        except UnsafeURL:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                pass
            else:
                raise
        else:
            literal_address = True
        if literal_address:
            answers = []
        else:
            try:
                answers = list(
                    resolver(
                        hostname,
                        port or (443 if parsed.scheme == "https" else 80),
                        type=socket.SOCK_STREAM,
                    )
                )
            except socket.gaierror as exc:
                if require_resolution:
                    raise UnsafeURL("webhook hostname could not be resolved") from exc
                # Configuration stays possible through transient DNS loss. Provider adapters must
                # call this validator again with require_resolution=True immediately before I/O.
                answers = []
            if require_resolution and not answers:
                raise UnsafeURL("webhook hostname did not resolve to an address")
        for answer in answers:
            socket_address = answer[4]
            if socket_address:
                _require_public_ip(str(socket_address[0]))
    normalized = SplitResult(
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.query,
        "",
    )
    return urlunsplit(normalized)


def _validate_monitoring_address(value: str, *, allow_private: bool) -> None:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise UnsafeURL("monitoring URL resolved to an invalid address") from exc
    if (
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise UnsafeURL("monitoring URL resolved to a link-local, reserved, or invalid address")
    if not allow_private and not address.is_global:
        raise UnsafeURL("private or loopback monitoring addresses require explicit opt-in")


def validate_monitoring_url(
    value: str,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
    resolver: Resolver = socket.getaddrinfo,
) -> str:
    """Validate a Prometheus base URL, including DNS at configuration/send time."""

    if len(value) > 2_048:
        raise UnsafeURL("monitoring URL is too long")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("monitoring URL is invalid") from exc
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise UnsafeURL("monitoring URL must use HTTPS unless HTTP is explicitly enabled")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise UnsafeURL("monitoring URL must contain a hostname and no embedded credentials")
    if parsed.query or parsed.fragment:
        raise UnsafeURL("monitoring URL must not contain a query or fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    if (
        hostname == "localhost" or hostname.endswith((".localhost", ".local"))
    ) and not allow_private:
        raise UnsafeURL("local monitoring hostnames require explicit private-network opt-in")

    addresses: list[str] = []
    try:
        ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        try:
            answers = resolver(
                hostname,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise UnsafeURL("monitoring hostname could not be resolved") from exc
        addresses = [str(answer[4][0]) for answer in answers if answer[4]]
        if not addresses:
            raise UnsafeURL("monitoring hostname did not resolve to an address") from None
    else:
        addresses = [hostname]
    for address in addresses:
        _validate_monitoring_address(address, allow_private=allow_private)

    normalized = SplitResult(
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path.rstrip("/") or "",
        "",
        "",
    )
    return urlunsplit(normalized)


def validate_headers(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise UnsafeURL("webhook headers must be an object")
    result: dict[str, str] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise UnsafeURL("webhook header name is invalid")
        if not isinstance(raw, str) or "\r" in raw or "\n" in raw:
            raise UnsafeURL("webhook header values must be strings without line breaks")
        result[name] = raw
    return result
