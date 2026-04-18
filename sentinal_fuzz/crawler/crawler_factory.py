"""Crawler factory — selects the right crawler based on config.

Usage::

    from sentinal_fuzz.crawler.crawler_factory import get_crawler

    crawler = await get_crawler(config, http_client)
    endpoints = await crawler.crawl(config.target)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentinal_fuzz.crawler.base import BaseCrawler
from sentinal_fuzz.crawler.http_crawler import HttpCrawler
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient

log = get_logger("crawler_factory")


def _playwright_available() -> bool:
    """Check if Playwright is installed and has browser binaries."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def get_crawler(
    config: ScanConfig,
    http_client: HttpClient,
    *,
    ignore_robots: bool = False,
) -> BaseCrawler:
    """Return the appropriate crawler based on configuration.

    Decision logic:
        - If ``config.js_rendering`` is True **and** Playwright is installed,
          return a ``JsCrawler``.
        - Otherwise return an ``HttpCrawler`` (with a warning if JS was
          requested but Playwright is unavailable).

    Args:
        config:        Scan configuration.
        http_client:   Shared async HTTP client.
        ignore_robots: Pass through to HttpCrawler.

    Returns:
        A ``BaseCrawler`` subclass instance ready to call ``.crawl(url)``.
    """
    if config.js_rendering:
        if _playwright_available():
            from sentinal_fuzz.crawler.js_crawler import JsCrawler

            log.info(
                "JS rendering enabled — using Playwright JsCrawler "
                "(concurrency=%d, depth=%d)",
                config.concurrency,
                config.depth,
            )
            return JsCrawler(config=config, http_client=http_client)
        else:
            log.warning(
                "JS rendering requested but Playwright is not installed. "
                "Falling back to HttpCrawler. "
                "Install Playwright: pip install playwright && playwright install chromium"
            )

    log.info(
        "Using HttpCrawler (concurrency=%d, depth=%d)",
        config.concurrency,
        config.depth,
    )
    return HttpCrawler(
        config=config,
        http_client=http_client,
        ignore_robots=ignore_robots,
    )
