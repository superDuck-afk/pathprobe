"""Async HTTP transport using aiohttp.

This is the ONLY module that contains async code.  All other modules
(payload engine, response analyzer, fingerprinter, etc.) are
synchronous and are called from within the async scan loop.

The transport provides:
  - Connection pooling (TCPConnector with keepalive)
  - Semaphore-based concurrency (true backpressure)
  - Token-bucket rate limiting
  - Per-URL baseline caching
  - Redirect following (configurable)
"""

from __future__ import annotations

import asyncio
import random
import time
import urllib.parse
from typing import Dict, Optional

import aiohttp

from pathprobe.core.types import Response
from pathprobe.core.config import USER_AGENTS


class AsyncTransport:
    """Async HTTP engine backed by aiohttp.

    Instantiate once per scan, pass to the scanner engine.
    The ``async with`` protocol manages the aiohttp session lifecycle.
    """

    def __init__(
        self,
        concurrency: int = 20,
        rate_limit: Optional[float] = None,    # requests/second
        timeout: int = 10,
        verify_ssl: bool = True,
        max_redirects: int = 5,
        retries: int = 2,
    ):
        self._concurrency = concurrency
        self._rate_interval = 1.0 / rate_limit if rate_limit else 0.0
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._verify_ssl = verify_ssl
        self._max_redirects = max_redirects
        self._retries = retries
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(concurrency)
        self._rate_lock = asyncio.Lock()
        self._last_request_time = 0.0
        self._baseline_cache: Dict[str, Response] = {}

    async def __aenter__(self) -> "AsyncTransport":
        connector = aiohttp.TCPConnector(
            limit=self._concurrency,
            limit_per_host=self._concurrency,
            ssl=None if self._verify_ssl else False,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()
            # Grace period for underlying connections to close
            await asyncio.sleep(0.25)

    # ── Rate limiting ─────────────────────────────────────────────

    async def _rate_wait(self) -> None:
        if self._rate_interval <= 0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            wait = self._rate_interval - (now - self._last_request_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

    # ── Core request ──────────────────────────────────────────────

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        cookies: Optional[str] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        """Send one HTTP request with retry + rate-limit + semaphore."""
        h = dict(headers or {})
        h.setdefault("User-Agent", random.choice(USER_AGENTS))
        if cookies:
            h["Cookie"] = cookies

        for attempt in range(self._retries + 1):
            async with self._semaphore:
                await self._rate_wait()
                try:
                    start = time.monotonic()
                    async with self._session.request(
                        method, url,
                        headers=h,
                        data=data,
                        allow_redirects=allow_redirects,
                        max_redirects=self._max_redirects,
                        ssl=None if self._verify_ssl else False,
                    ) as resp:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        elapsed = round(time.monotonic() - start, 3)
                        return Response(
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body,
                            length=len(body),
                            elapsed=elapsed,
                            url=str(resp.url),
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    if attempt < self._retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    return None
        return None

    # ── Convenience methods ───────────────────────────────────────

    async def get(
        self,
        url: str,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> Optional[Response]:
        """GET request, optionally injecting *payload* into *param*."""
        final_url = url
        if param and payload:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            final_url = parsed._replace(
                query=urllib.parse.urlencode(qs, doseq=True),
            ).geturl()
        return await self.request(final_url, "GET",
                                   headers=extra_headers, cookies=cookies)

    async def post(
        self,
        url: str,
        data: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> Optional[Response]:
        """POST request with pre-built body."""
        return await self.request(url, "POST", headers=extra_headers,
                                   data=data, cookies=cookies)

    # ── Baseline caching ──────────────────────────────────────────

    async def get_baseline(
        self,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> Optional[Response]:
        """Fetch baseline once per URL and cache it."""
        if url not in self._baseline_cache:
            resp = await self.request(url, "GET",
                                       headers=extra_headers, cookies=cookies)
            if resp:
                self._baseline_cache[url] = resp
        return self._baseline_cache.get(url)

    def get_cached_baseline(self, url: str) -> Optional[Response]:
        """Get a previously cached baseline (sync access)."""
        return self._baseline_cache.get(url)
