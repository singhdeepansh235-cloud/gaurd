"""HTTP client wrapper for Sentinal-Fuzz.

Thin async wrapper around ``httpx.AsyncClient`` that adds:
- Configurable timeout and retry (3x by default)
- User-Agent rotation from a realistic browser list
- Baseline response recording for differential analysis
- Rate limiting integration hook
- Structured logging of all requests

Usage::

    from sentinal_fuzz.utils.http import HttpClient

    async with HttpClient(timeout=10, proxy="http://127.0.0.1:8080") as client:
        response = await client.get("https://example.com/login")
        print(response.status_code, len(response.text))
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

import httpx

from sentinal_fuzz.utils.logger import get_logger

log = get_logger("http")

# ── User-Agent pool ────────────────────────────────────────────────
# Realistic browser UAs to avoid trivial bot detection.
_USER_AGENTS: list[str] = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0)"
        " Gecko/20100101 Firefox/128.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0)"
        " Gecko/20100101 Firefox/128.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
    ),
]


@dataclass
class Response:
    """Simplified HTTP response container.

    Wraps httpx.Response into a lightweight dataclass for easier
    consumption by the fuzzer and analyzer.

    Attributes:
        status_code:  HTTP status code.
        headers:      Response headers as a dict.
        text:         Decoded response body.
        elapsed_ms:   Round-trip time in milliseconds.
        url:          Final URL after redirects.
        is_redirect:  Whether a redirect occurred.
    """

    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    url: str
    is_redirect: bool = False

    @classmethod
    def from_httpx(cls, resp: httpx.Response, elapsed_ms: float) -> Response:
        """Create a Response from an httpx.Response."""
        return cls(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            elapsed_ms=elapsed_ms,
            url=str(resp.url),
            is_redirect=resp.is_redirect,
        )


@dataclass
class HttpClient:
    """Async HTTP client with retry, UA rotation, and baseline recording.

    Designed as an async context manager::

        async with HttpClient(timeout=10) as client:
            resp = await client.get(url)

    Attributes:
        timeout:       Request timeout in seconds.
        max_retries:   Maximum retry attempts on failure.
        proxy:         Optional HTTP/SOCKS proxy URL.
        verify_ssl:    Whether to verify TLS certificates.
        follow_redirects: Whether to follow HTTP redirects.
        rotate_ua:     Whether to rotate User-Agent per request.
        default_headers: Headers applied to every request.
    """

    timeout: int = 10
    max_retries: int = 3
    proxy: str | None = None
    verify_ssl: bool = True
    follow_redirects: bool = True
    rotate_ua: bool = True
    default_headers: dict[str, str] = field(default_factory=dict)

    # Internal state (not user-configurable)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)
    _request_count: int = field(default=0, init=False, repr=False)
    _baselines: dict[str, Response] = field(default_factory=dict, init=False, repr=False)

    async def __aenter__(self) -> Self:
        """Initialize the underlying httpx.AsyncClient."""
        transport = httpx.AsyncHTTPTransport(retries=0)  # We handle retries ourselves
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=self.follow_redirects,
            verify=self.verify_ssl,
            proxy=self.proxy,
            transport=transport,
            http2=True,
        )
        log.debug("HTTP client initialized (timeout=%ds, proxy=%s)", self.timeout, self.proxy)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the underlying httpx.AsyncClient."""
        if self._client:
            await self._client.aclose()
            log.debug("HTTP client closed (total requests: %d)", self._request_count)

    def _pick_user_agent(self) -> str:
        """Select a User-Agent string."""
        if self.rotate_ua:
            return random.choice(_USER_AGENTS)
        return _USER_AGENTS[0]

    def _build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Merge default headers, UA, and request-specific headers."""
        headers = {
            "User-Agent": self._pick_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
        headers.update(self.default_headers)
        if extra:
            headers.update(extra)
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> Response:
        """Execute an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.).
            url:    Request URL.
            **kwargs: Additional arguments passed to httpx.

        Returns:
            A ``Response`` dataclass.

        Raises:
            httpx.HTTPError: If all retries are exhausted.
        """
        if self._client is None:
            raise RuntimeError(
                "HttpClient must be used as an async context manager: "
                "'async with HttpClient() as client:...'"
            )

        headers = self._build_headers(kwargs.pop("headers", None))
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                start = time.monotonic()
                resp = await self._client.request(
                    method, url, headers=headers, **kwargs
                )
                elapsed_ms = (time.monotonic() - start) * 1000

                self._request_count += 1
                response = Response.from_httpx(resp, elapsed_ms)

                log.debug(
                    "%s %s → %d (%.0fms)",
                    method, url, response.status_code, elapsed_ms,
                )
                return response

            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as exc:
                last_error = exc
                if attempt < self.max_retries:
                    wait = 2 ** (attempt - 1)  # Exponential backoff: 1s, 2s
                    log.warning(
                        "%s %s failed (attempt %d/%d): %s — retrying in %ds",
                        method, url, attempt, self.max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    log.error(
                        "%s %s failed after %d attempts: %s",
                        method, url, self.max_retries, exc,
                    )

        raise httpx.HTTPError(
            f"Request to {url} failed after {self.max_retries} retries"
        ) from last_error

    async def get(self, url: str, **kwargs: Any) -> Response:
        """Send a GET request.

        Args:
            url:      Request URL.
            **kwargs: Additional httpx arguments (params, cookies, etc.).

        Returns:
            A ``Response`` dataclass.
        """
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        """Send a POST request.

        Args:
            url:      Request URL.
            **kwargs: Additional httpx arguments (data, json, etc.).

        Returns:
            A ``Response`` dataclass.
        """
        return await self._request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        """Send a request with any HTTP method.

        Args:
            method:   HTTP method string (GET, POST, PUT, DELETE, etc.).
            url:      Request URL.
            **kwargs: Additional httpx arguments.

        Returns:
            A ``Response`` dataclass.
        """
        return await self._request(method, url, **kwargs)

    async def record_baseline(self, url: str) -> Response:
        """Record a baseline response for differential analysis.

        Sends a clean GET request (no payloads) and stores the response.
        The fuzzer can later compare fuzzed responses against baselines
        to detect anomalies.

        Args:
            url: The URL to baseline.

        Returns:
            The baseline ``Response``.
        """
        response = await self.get(url)
        self._baselines[url] = response
        log.debug("Recorded baseline for %s (status=%d)", url, response.status_code)
        return response

    def get_baseline(self, url: str) -> Response | None:
        """Retrieve a previously recorded baseline response.

        Args:
            url: The URL to look up.

        Returns:
            The baseline ``Response``, or None if not recorded.
        """
        return self._baselines.get(url)

    @property
    def request_count(self) -> int:
        """Total number of HTTP requests sent by this client."""
        return self._request_count
