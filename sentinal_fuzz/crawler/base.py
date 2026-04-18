"""Abstract base crawler for Sentinal-Fuzz.

All crawler implementations (basic HTTP crawler, Playwright JS-rendering
crawler, sitemap parser, API spec crawler) extend ``BaseCrawler`` and
implement the ``crawl()`` coroutine.

Usage::

    class HttpCrawler(BaseCrawler):
        async def crawl(self, url: str) -> list[Endpoint]:
            ...

    crawler = HttpCrawler(config=scan_config, http_client=client)
    endpoints = await crawler.crawl("https://example.com")
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Endpoint
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient

log = get_logger("crawler")


@dataclass
class CrawlState:
    """Mutable state tracked during a crawl session.

    Attributes:
        visited:    Set of already-visited URLs (normalized).
        queue:      Ordered list of URLs still to visit.
        endpoints:  All discovered endpoints so far.
        depth_map:  Mapping of URL → crawl depth at which it was found.
        errors:     URLs that failed with their error messages.
    """

    visited: set[str] = field(default_factory=set)
    queue: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    depth_map: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def urls_remaining(self) -> int:
        """Number of URLs still in the crawl queue."""
        return len(self.queue)

    def mark_visited(self, url: str, depth: int) -> None:
        """Mark a URL as visited at a given depth."""
        self.visited.add(url)
        self.depth_map[url] = depth

    def should_visit(self, url: str) -> bool:
        """Check if a URL should be visited (not already seen)."""
        return url not in self.visited


class BaseCrawler(abc.ABC):
    """Abstract base class for all crawlers.

    Subclasses must implement:
        - ``crawl(url) -> list[Endpoint]``: Discover endpoints from a URL.

    Optionally override:
        - ``normalize_url(url)``: URL normalization logic.
        - ``is_in_scope(url)``: Scope restriction logic.
        - ``extract_links(html)``: Link extraction from HTML content.

    Attributes:
        config:      The scan configuration.
        http_client: Shared HTTP client instance.
        state:       Mutable crawl state tracking visited URLs and queue.
    """

    def __init__(
        self,
        config: ScanConfig,
        http_client: HttpClient,
    ) -> None:
        self.config = config
        self.http_client = http_client
        self.state = CrawlState()
        self._on_url_found_callbacks: list[callable] = []  # type: ignore[type-arg]

    def on_url_found(self, callback: callable) -> None:  # type: ignore[type-arg]
        """Register a callback to be invoked when a new URL is discovered.

        Args:
            callback: A callable that receives the discovered URL string.
        """
        self._on_url_found_callbacks.append(callback)

    def _notify_url_found(self, url: str) -> None:
        """Fire all registered on_url_found callbacks."""
        for cb in self._on_url_found_callbacks:
            try:
                cb(url)
            except Exception as exc:
                log.warning("on_url_found callback error: %s", exc)

    @abc.abstractmethod
    async def crawl(self, url: str) -> list[Endpoint]:
        """Discover endpoints starting from the given URL.

        Implementations should:
        1. Fetch the page at ``url``
        2. Extract links, forms, and input vectors
        3. Recursively discover new pages up to ``config.depth``
        4. Return all discovered ``Endpoint`` objects

        Args:
            url: The starting URL to crawl from.

        Returns:
            A list of discovered ``Endpoint`` objects.
        """
        ...

    def normalize_url(self, url: str) -> str:
        """Normalize a URL for deduplication.

        Strips fragments, trailing slashes, and normalizes query param order.
        Override this for custom normalization logic.

        Args:
            url: Raw URL string.

        Returns:
            Normalized URL string.
        """
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        parsed = urlparse(url)
        # Remove fragment, sort query params, strip trailing slash
        sorted_query = urlencode(sorted(parse_qsl(parsed.query)))
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") or "/",
            parsed.params,
            sorted_query,
            "",  # drop fragment
        ))
        return normalized

    def is_in_scope(self, url: str) -> bool:
        """Check whether a URL is within the configured scan scope.

        By default, restricts to the same domain as the target. Override
        for custom scope rules.

        Args:
            url: URL to check.

        Returns:
            True if the URL is within scope.
        """
        import re
        from urllib.parse import urlparse

        target_host = urlparse(self.config.target).netloc
        url_host = urlparse(url).netloc

        if url_host != target_host:
            return False

        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if re.search(pattern, url):
                return False

        # Check scope patterns (if any are specified, URL must match at least one)
        if self.config.scope_patterns:
            return any(re.search(p, url) for p in self.config.scope_patterns)

        return True
