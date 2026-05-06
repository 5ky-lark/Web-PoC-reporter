"""
Per-host request throttle + cancel token + raw HTTP capture.

Wraps httpx.AsyncClient with:
  1. A per-host asyncio.Semaphore to cap concurrent in-flight requests
  2. A token bucket for soft RPS limit
  3. A cancel event that scanners can check to bail out mid-run
  4. An event hook that captures raw req/resp pairs for evidence
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx


@dataclass
class HostThrottle:
    """Per-host concurrency cap + token-bucket rate limit."""
    concurrency: int = 4
    rps: float = 8.0  # tokens per second; bucket size = rps
    _semaphores: dict[str, asyncio.Semaphore] = field(default_factory=dict)
    _bucket: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def _sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._semaphores:
            self._semaphores[host] = asyncio.Semaphore(self.concurrency)
        return self._semaphores[host]

    async def _take_token(self, host: str) -> None:
        """Token bucket: at most `self.rps` requests per rolling 1s window."""
        if self.rps <= 0:
            return
        now = time.monotonic()
        bucket = self._bucket[host]
        bucket[:] = [t for t in bucket if now - t < 1.0]
        while len(bucket) >= self.rps:
            sleep_for = 1.0 - (now - bucket[0]) + 0.005
            await asyncio.sleep(max(sleep_for, 0.005))
            now = time.monotonic()
            bucket[:] = [t for t in bucket if now - t < 1.0]
        bucket.append(now)

    @asynccontextmanager
    async def slot(self, host: str):
        sem = self._sem(host)
        await self._take_token(host)
        async with sem:
            yield


@dataclass
class CancelToken:
    """Cooperative cancellation. Scanners check `is_cancelled` between probes."""
    _event: asyncio.Event = field(default_factory=asyncio.Event)

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise CancelledScan()


class CancelledScan(Exception):
    """Raised when a scan is killed by the operator."""


# Module-global. Orchestrator wires per-scan cancel tokens through here.
THROTTLE = HostThrottle(concurrency=4, rps=8.0)


def host_of(url: str) -> str:
    p = urlparse(url)
    return (p.hostname or "").lower()


# -------- raw HTTP capture --------

def serialize_request(method: str, url: str, headers: Optional[dict] = None,
                      body: Optional[str] = None) -> str:
    """Render a raw HTTP request for evidence display. RFC 7230-ish."""
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {p.netloc}"]
    if headers:
        for k, v in headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def serialize_response(resp: httpx.Response, body_limit: int = 4096) -> str:
    """Render a raw HTTP response for evidence display, body truncated."""
    status_line = f"HTTP/{resp.http_version} {resp.status_code} {resp.reason_phrase}"
    lines = [status_line]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    body = resp.text or ""
    if len(body) > body_limit:
        body = body[:body_limit] + f"\n... [truncated {len(body) - body_limit} bytes]"
    lines.append(body)
    return "\n".join(lines)


def build_curl(method: str, url: str, headers: Optional[dict] = None,
               body: Optional[str] = None) -> str:
    """Build a single-line curl reproducer."""
    parts = ["curl", "-i", "-X", method.upper()]
    if headers:
        for k, v in headers.items():
            v_safe = str(v).replace("'", "'\\''")
            parts.append(f"-H '{k}: {v_safe}'")
    if body:
        body_safe = body.replace("'", "'\\''")
        parts.append(f"--data-raw '{body_safe}'")
    url_safe = url.replace("'", "'\\''")
    parts.append(f"'{url_safe}'")
    return " ".join(parts)


def capture(method: str, url: str, resp: httpx.Response,
            req_headers: Optional[dict] = None,
            req_body: Optional[str] = None) -> dict:
    """Bundle raw req/resp/curl for a Finding."""
    return {
        "evidence_request": serialize_request(method, url, req_headers, req_body),
        "evidence_response": serialize_response(resp),
        "evidence_curl": build_curl(method, url, req_headers, req_body),
    }
