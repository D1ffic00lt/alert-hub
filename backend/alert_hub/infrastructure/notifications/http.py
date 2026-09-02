from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from alert_hub.application.notifications import DeliveryOutcome


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status_code: int


class HTTPTransportTimeout(Exception):
    pass


class HTTPTransportError(Exception):
    pass


class HTTPTransport(Protocol):
    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
        timeout_seconds: float,
    ) -> HTTPResponse: ...


class HttpxTransport:
    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
        timeout_seconds: float,
    ) -> HTTPResponse:
        timeout = httpx.Timeout(timeout_seconds)
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request("POST", url, headers=headers, content=content)
                # Only the status is part of the provider contract. Streaming prevents an
                # untrusted endpoint from forcing an arbitrary response body into memory.
                response = await client.send(request, stream=True)
                status_code = response.status_code
                await response.aclose()
        except httpx.TimeoutException as exc:
            raise HTTPTransportTimeout from exc
        except httpx.HTTPError as exc:
            raise HTTPTransportError from exc
        return HTTPResponse(status_code=status_code)


def classify_http_status(status_code: int) -> DeliveryOutcome:
    if 200 <= status_code < 300:
        return "succeeded"
    if status_code in {408, 409, 425, 429} or 500 <= status_code < 600:
        return "retryable"
    return "permanent"
