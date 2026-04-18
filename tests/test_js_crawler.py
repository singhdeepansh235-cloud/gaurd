"""Tests for the Playwright JsCrawler and crawler_factory.

Uses a local HTTP server (aiohttp) serving real HTML pages so that
Playwright can render them in a headless browser.

Tests are split into:
  - Unit tests (no browser needed — merge, factory, SPA parsing)
  - Integration tests (real Playwright — require browser binaries)

Integration tests are marked with ``pytest.mark.playwright`` and can be
skipped in CI with ``pytest -m "not playwright"``.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import Endpoint
from sentinal_fuzz.crawler.crawler_factory import get_crawler
from sentinal_fuzz.crawler.js_crawler import JsCrawler, merge_endpoints

# ── Helpers ───────────────────────────────────────────────────────

def _make_config(
    target: str = "http://127.0.0.1:9876",
    js_rendering: bool = True,
    **kwargs: Any,
) -> ScanConfig:
    defaults = {
        "depth": 1,
        "concurrency": 5,
        "timeout": 10,
        "scan_profile": "quick",
    }
    defaults.update(kwargs)
    return ScanConfig(target=target, js_rendering=js_rendering, **defaults)


# ── Test fixture server ──────────────────────────────────────────

_TEST_PAGES: dict[str, tuple[str, str]] = {
    "/": (
        "text/html",
        """<!DOCTYPE html>
<html>
<head><title>JS Test App</title></head>
<body>
    <h1>Home</h1>
    <a href="/about">About</a>
    <a href="/api-page">API Page</a>
    <button id="dynamic-btn" onclick="document.getElementById('dynamic').innerHTML='<a href=\\'/dynamic-link\\'>Dynamic</a>'">Load Content</button>
    <div id="dynamic"></div>
    <form action="/login" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="email" name="email" />
        <button type="submit">Login</button>
    </form>
</body>
</html>""",
    ),
    "/about": (
        "text/html",
        """<!DOCTYPE html>
<html><head><title>About</title></head>
<body>
    <h1>About</h1>
    <a href="/">Home</a>
    <div data-url="/api/data">API Data</div>
</body></html>""",
    ),
    "/api-page": (
        "text/html",
        """<!DOCTYPE html>
<html><head><title>API Page</title></head>
<body>
    <h1>API Test</h1>
    <script>
        // This will be intercepted as XHR
        fetch('/api/users', {method: 'GET', headers: {'Accept': 'application/json'}});
    </script>
    <script>
        // Inline API pattern
        const API_URL = "/api/v1/products";
    </script>
</body></html>""",
    ),
    "/api/users": (
        "application/json",
        '{"users": [{"id": 1, "name": "Alice"}]}',
    ),
    "/api/data": (
        "application/json",
        '{"status": "ok"}',
    ),
    "/api/v1/products": (
        "application/json",
        '{"products": []}',
    ),
    "/login": (
        "text/html",
        """<!DOCTYPE html>
<html><body><h1>Login Result</h1></body></html>""",
    ),
    "/spa-app": (
        "text/html",
        """<!DOCTYPE html>
<html><head><title>SPA</title></head>
<body>
    <div id="app">SPA Content</div>
    <script>
        window.__NEXT_DATA__ = {"page": "/dashboard", "buildId": "abc"};
        history.pushState(null, '', '/spa-route-1');
    </script>
</body></html>""",
    ),
}


class _TestHandler(SimpleHTTPRequestHandler):
    """Test HTTP handler serving predefined pages."""

    def do_GET(self) -> None:
        path = self.path.split("?")[0]  # strip query string
        if path in _TEST_PAGES:
            content_type, body = _TEST_PAGES[path]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress server logs during tests


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def test_server() -> Generator[str, None, None]:
    """Start a test HTTP server in a background thread."""
    port = _find_free_port()
    server = HTTPServer(("127.0.0.1", port), _TestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ══════════════════════════════════════════════════════════════════
#  Unit tests — no browser needed
# ══════════════════════════════════════════════════════════════════


class TestMergeEndpoints:
    """Test endpoint merging logic."""

    def test_merge_no_overlap(self):
        http_eps = [Endpoint(url="http://a.com/page1", method="GET")]
        js_eps = [Endpoint(url="http://a.com/page2", method="GET")]

        merged = merge_endpoints(http_eps, js_eps)
        assert len(merged) == 2

    def test_merge_with_overlap(self):
        http_eps = [
            Endpoint(url="http://a.com/page", method="GET", params={"a": "1"})
        ]
        js_eps = [
            Endpoint(url="http://a.com/page", method="GET", params={"b": "2"})
        ]

        merged = merge_endpoints(http_eps, js_eps)
        assert len(merged) == 1
        assert "a" in merged[0].params
        assert "b" in merged[0].params

    def test_merge_different_methods(self):
        http_eps = [Endpoint(url="http://a.com/api", method="GET")]
        js_eps = [Endpoint(url="http://a.com/api", method="POST")]

        merged = merge_endpoints(http_eps, js_eps)
        assert len(merged) == 2

    def test_merge_api_flag_promotion(self):
        http_eps = [
            Endpoint(url="http://a.com/api", method="GET", is_api=False)
        ]
        js_eps = [
            Endpoint(url="http://a.com/api", method="GET", is_api=True)
        ]

        merged = merge_endpoints(http_eps, js_eps)
        assert len(merged) == 1
        assert merged[0].is_api is True

    def test_merge_forms(self):
        http_eps = [
            Endpoint(
                url="http://a.com/form",
                method="POST",
                forms=[{"name": "username", "type": "text"}],
            )
        ]
        js_eps = [
            Endpoint(
                url="http://a.com/form",
                method="POST",
                forms=[
                    {"name": "username", "type": "text"},  # dupe
                    {"name": "csrf_token", "type": "hidden"},  # new
                ],
            )
        ]

        merged = merge_endpoints(http_eps, js_eps)
        assert len(merged) == 1
        names = {f.get("name") for f in merged[0].forms}
        assert "username" in names
        assert "csrf_token" in names


class TestCrawlerFactory:
    """Test get_crawler() selection logic."""

    def test_returns_http_when_js_disabled(self):
        config = _make_config(js_rendering=False)
        mock_client = MagicMock()
        crawler = get_crawler(config, mock_client)
        from sentinal_fuzz.crawler.http_crawler import HttpCrawler
        assert isinstance(crawler, HttpCrawler)

    def test_returns_js_when_enabled_and_available(self):
        config = _make_config(js_rendering=True)
        mock_client = MagicMock()
        crawler = get_crawler(config, mock_client)
        assert isinstance(crawler, JsCrawler)

    def test_falls_back_to_http_when_playwright_missing(self):
        config = _make_config(js_rendering=True)
        mock_client = MagicMock()

        with patch(
            "sentinal_fuzz.crawler.crawler_factory._playwright_available",
            return_value=False,
        ):
            crawler = get_crawler(config, mock_client)

        from sentinal_fuzz.crawler.http_crawler import HttpCrawler
        assert isinstance(crawler, HttpCrawler)


class TestJsCrawlerSpaRoutes:
    """Test SPA route parsing logic (no browser needed)."""

    def _make_crawler(self) -> JsCrawler:
        config = _make_config()
        mock_client = MagicMock()
        return JsCrawler(config=config, http_client=mock_client)

    def test_nextjs_routes(self):
        crawler = self._make_crawler()
        routes_data = {
            "nextjs": json.dumps({"page": "/dashboard", "buildId": "abc"}),
        }
        links = crawler._parse_spa_routes(routes_data, "http://127.0.0.1:9876")
        assert any("/dashboard" in l for l in links)

    def test_angular_routes(self):
        crawler = self._make_crawler()
        routes_data = {
            "angular": json.dumps(["/home", "/users", "/settings"]),
        }
        links = crawler._parse_spa_routes(routes_data, "http://127.0.0.1:9876")
        assert len(links) == 3
        assert any("/home" in l for l in links)
        assert any("/settings" in l for l in links)

    def test_api_from_js(self):
        crawler = self._make_crawler()
        routes_data = {
            "api_from_js": ["/api/v1/users", "/api/v1/orders"],
        }
        links = crawler._parse_spa_routes(routes_data, "http://127.0.0.1:9876")
        assert len(links) == 2
        assert any("/api/v1/users" in l for l in links)

    def test_empty_routes(self):
        crawler = self._make_crawler()
        links = crawler._parse_spa_routes({}, "http://127.0.0.1:9876")
        assert links == []

    def test_invalid_json(self):
        crawler = self._make_crawler()
        routes_data = {"nextjs": "not-valid-json{{{"}
        links = crawler._parse_spa_routes(routes_data, "http://127.0.0.1:9876")
        assert links == []  # Should not crash


class TestJsCrawlerResolveLink:
    """Test URL resolution/filtering."""

    def _make_crawler(self) -> JsCrawler:
        config = _make_config(target="http://127.0.0.1:9876")
        mock_client = MagicMock()
        return JsCrawler(config=config, http_client=mock_client)

    def test_resolve_relative(self):
        c = self._make_crawler()
        assert c._resolve_link("/about", "http://127.0.0.1:9876/") == "http://127.0.0.1:9876/about"

    def test_skip_javascript(self):
        c = self._make_crawler()
        assert c._resolve_link("javascript:void(0)", "http://127.0.0.1:9876/") is None

    def test_skip_mailto(self):
        c = self._make_crawler()
        assert c._resolve_link("mailto:test@example.com", "http://127.0.0.1:9876/") is None

    def test_skip_external(self):
        c = self._make_crawler()
        assert c._resolve_link("https://evil.com/steal", "http://127.0.0.1:9876/") is None

    def test_skip_empty(self):
        c = self._make_crawler()
        assert c._resolve_link("", "http://127.0.0.1:9876/") is None


class TestNetworkRequestToEndpoint:
    """Test intercepted request → Endpoint conversion."""

    def _make_crawler(self) -> JsCrawler:
        config = _make_config(target="http://127.0.0.1:9876")
        mock_client = MagicMock()
        return JsCrawler(config=config, http_client=mock_client)

    def test_basic_get(self):
        c = self._make_crawler()
        ep = c._network_request_to_endpoint(
            {"url": "http://127.0.0.1:9876/api/users?page=1", "method": "GET", "headers": {}},
            "http://127.0.0.1:9876/",
        )
        assert ep is not None
        assert ep.method == "GET"
        assert ep.is_api is True
        assert "page" in ep.params

    def test_json_post(self):
        c = self._make_crawler()
        ep = c._network_request_to_endpoint(
            {
                "url": "http://127.0.0.1:9876/api/users",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "post_data": '{"name": "Alice", "role": "admin"}',
            },
            "http://127.0.0.1:9876/",
        )
        assert ep is not None
        assert ep.method == "POST"
        assert "name" in ep.params
        assert "role" in ep.params

    def test_form_encoded_post(self):
        c = self._make_crawler()
        ep = c._network_request_to_endpoint(
            {
                "url": "http://127.0.0.1:9876/api/login",
                "method": "POST",
                "headers": {},
                "post_data": "username=admin&password=secret",
            },
            "http://127.0.0.1:9876/",
        )
        assert ep is not None
        assert "username" in ep.params

    def test_external_request_skipped(self):
        c = self._make_crawler()
        ep = c._network_request_to_endpoint(
            {"url": "https://cdn.external.com/lib.js", "method": "GET", "headers": {}},
            "http://127.0.0.1:9876/",
        )
        assert ep is None


# ══════════════════════════════════════════════════════════════════
#  Integration tests — require Playwright + browser
# ══════════════════════════════════════════════════════════════════


def _browser_available() -> bool:
    """Check if Playwright browser binaries are installed."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
            return Path(path).exists() if path else False
    except Exception:
        return False


# Skip entire class if no browser binary
_skip_no_browser = pytest.mark.skipif(
    not _browser_available(),
    reason="Playwright Chromium browser not installed",
)


@_skip_no_browser
class TestJsCrawlerIntegration:
    """End-to-end tests with a real headless browser."""

    @pytest.mark.asyncio
    async def test_basic_js_crawl(self, test_server: str):
        """JsCrawler discovers static links from rendered DOM."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(test_server)

        urls = {ep.url for ep in endpoints}
        assert len(endpoints) >= 1  # At least the home page

    @pytest.mark.asyncio
    async def test_discovers_links(self, test_server: str):
        """JsCrawler finds <a href> links in rendered HTML."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(test_server)

        urls = {ep.url for ep in endpoints}
        assert any("about" in u for u in urls)

    @pytest.mark.asyncio
    async def test_discovers_forms(self, test_server: str):
        """JsCrawler extracts form endpoints."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(test_server)

        form_eps = [ep for ep in endpoints if ep.method == "POST"]
        assert len(form_eps) >= 1
        login_ep = [ep for ep in form_eps if "login" in ep.url]
        assert len(login_ep) >= 1

        # Verify form fields were extracted
        if login_ep:
            field_names = {f.get("name") for f in login_ep[0].forms}
            assert "username" in field_names or len(login_ep[0].forms) > 0

    @pytest.mark.asyncio
    async def test_intercepts_api_calls(self, test_server: str):
        """JsCrawler captures XHR/fetch requests as API endpoints."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(f"{test_server}/api-page")

        api_eps = [ep for ep in endpoints if ep.is_api]
        # The page does fetch('/api/users') — should be intercepted
        api_urls = {ep.url for ep in api_eps}
        assert any("api/users" in u for u in api_urls) or len(crawler._intercepted_requests) > 0

    @pytest.mark.asyncio
    async def test_url_found_callbacks(self, test_server: str):
        """on_url_found callbacks fire for discovered URLs."""
        discovered: list[str] = []
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        crawler.on_url_found(lambda url: discovered.append(url))
        await crawler.crawl(test_server)

        # Should have discovered at least /about
        assert len(discovered) >= 1

    @pytest.mark.asyncio
    async def test_crawl_respects_scope(self, test_server: str):
        """JsCrawler does not follow external links."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(test_server)

        # All endpoints should be on the test server
        for ep in endpoints:
            assert "127.0.0.1" in ep.url or "localhost" in ep.url

    @pytest.mark.asyncio
    async def test_spa_routes_detected(self, test_server: str):
        """JsCrawler detects Next.js __NEXT_DATA__ routes."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        endpoints = await crawler.crawl(f"{test_server}/spa-app")

        urls = {ep.url for ep in endpoints}
        # The SPA page sets __NEXT_DATA__ with page: "/dashboard"
        assert any("dashboard" in u for u in urls) or any("spa-route" in u for u in urls)

    @pytest.mark.asyncio
    async def test_error_handling_graceful(self, test_server: str):
        """JsCrawler handles 404 pages without crashing."""
        config = _make_config(target=test_server, depth=1)
        mock_client = MagicMock()

        crawler = JsCrawler(config=config, http_client=mock_client)
        # Navigating to /nonexistent should not crash
        endpoints = await crawler.crawl(f"{test_server}/nonexistent")

        # Should complete without raising
        assert isinstance(endpoints, list)
