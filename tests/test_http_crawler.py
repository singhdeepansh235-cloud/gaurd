"""Tests for the HTTP crawler — async BFS, link extraction, forms, robots, fingerprinting.

Uses ``respx`` to mock httpx responses so no real network calls are made.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import Endpoint
from sentinal_fuzz.crawler.http_crawler import (
    HttpCrawler,
    RobotsRules,
    _ExtractedData,
    _is_html_content,
    classify_field,
    extract_page_data,
    fingerprint_technology,
    parse_robots_txt,
)
from sentinal_fuzz.utils.http import HttpClient


# ── Helpers ───────────────────────────────────────────────────────

def _make_config(target: str = "https://example.com", **kwargs) -> ScanConfig:
    """Build a ScanConfig with sensible test defaults."""
    defaults = {
        "depth": 2,
        "concurrency": 5,
        "timeout": 5,
        "scan_profile": "quick",
    }
    defaults.update(kwargs)
    return ScanConfig(target=target, **defaults)


def _html_page(body: str, title: str = "Test") -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


# ══════════════════════════════════════════════════════════════════
#  Unit tests — pure functions (no network)
# ══════════════════════════════════════════════════════════════════


class TestClassifyField:
    def test_id_field(self):
        assert classify_field("user_id", "text") == "id_field"
        assert classify_field("id", "text") == "id_field"
        assert classify_field("uid", "hidden") == "id_field"

    def test_search_field(self):
        assert classify_field("q", "text") == "search_field"
        assert classify_field("query", "text") == "search_field"
        assert classify_field("search", "text") == "search_field"

    def test_url_field(self):
        assert classify_field("redirect", "hidden") == "url_field"
        assert classify_field("next", "hidden") == "url_field"
        assert classify_field("return_url", "text") == "url_field"

    def test_file_field(self):
        assert classify_field("avatar", "file") == "file_field"

    def test_email_field(self):
        assert classify_field("email", "email") == "email_field"

    def test_generic(self):
        assert classify_field("first_name", "text") == "generic_text"
        assert classify_field("comment", "text") == "generic_text"


class TestRobotsTxt:
    def test_parse_basic(self):
        body = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /private/\n"
            "Allow: /admin/public/\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        )
        rules = parse_robots_txt(body)
        assert "/admin/" in rules.disallowed
        assert "/private/" in rules.disallowed
        assert "/admin/public/" in rules.allowed
        assert "https://example.com/sitemap.xml" in rules.sitemaps

    def test_is_allowed(self):
        rules = RobotsRules(
            disallowed=["/admin/", "/private/"],
            allowed=["/admin/public/"],
        )
        assert rules.is_allowed("/") is True
        assert rules.is_allowed("/about") is True
        assert rules.is_allowed("/admin/") is False
        assert rules.is_allowed("/admin/settings") is False
        assert rules.is_allowed("/admin/public/page") is True
        assert rules.is_allowed("/private/secret") is False

    def test_empty_robots(self):
        rules = parse_robots_txt("")
        assert rules.disallowed == []
        assert rules.is_allowed("/anything") is True

    def test_comments_ignored(self):
        body = (
            "# This is a comment\n"
            "User-agent: *\n"
            "Disallow: /secret/ # no access\n"
        )
        rules = parse_robots_txt(body)
        assert "/secret/" in rules.disallowed

    def test_other_user_agents_ignored(self):
        body = (
            "User-agent: Googlebot\n"
            "Disallow: /google-only/\n"
            "\n"
            "User-agent: *\n"
            "Disallow: /general/\n"
        )
        rules = parse_robots_txt(body)
        assert "/general/" in rules.disallowed
        assert "/google-only/" not in rules.disallowed


class TestExtractPageData:
    def test_extract_links(self):
        html = _html_page(
            '<a href="/about">About</a>'
            '<a href="https://example.com/contact">Contact</a>'
        )
        data = extract_page_data(html)
        assert "/about" in data.links
        assert "https://example.com/contact" in data.links

    def test_extract_forms(self):
        html = _html_page(
            '<form action="/login" method="POST">'
            '  <input type="text" name="username" value="">'
            '  <input type="password" name="password" value="">'
            '  <button type="submit" name="submit" value="Login">Login</button>'
            '</form>'
        )
        data = extract_page_data(html)
        assert len(data.forms) == 1
        form = data.forms[0]
        assert form["action"] == "/login"
        assert form["method"] == "POST"
        assert len(form["fields"]) == 3
        names = [f["name"] for f in form["fields"]]
        assert "username" in names
        assert "password" in names

    def test_extract_textarea(self):
        html = _html_page(
            '<form action="/comment" method="POST">'
            '  <textarea name="body"></textarea>'
            '</form>'
        )
        data = extract_page_data(html)
        assert len(data.forms) == 1
        field_names = [f["name"] for f in data.forms[0]["fields"]]
        assert "body" in field_names

    def test_extract_select(self):
        html = _html_page(
            '<form action="/filter" method="GET">'
            '  <select name="category">'
            '    <option value="all">All</option>'
            '    <option value="tech">Tech</option>'
            '  </select>'
            '</form>'
        )
        data = extract_page_data(html)
        assert len(data.forms) == 1
        field = [f for f in data.forms[0]["fields"] if f["name"] == "category"][0]
        assert field["type"] == "select"

    def test_extract_script_src(self):
        html = _html_page(
            '<script src="/static/app.js"></script>'
            '<script src="https://cdn.example.com/lib.js"></script>'
        )
        data = extract_page_data(html)
        assert "/static/app.js" in data.script_srcs
        assert "https://cdn.example.com/lib.js" in data.script_srcs

    def test_extract_data_attributes(self):
        html = _html_page(
            '<div data-url="/api/data" data-href="/detail">Content</div>'
        )
        data = extract_page_data(html)
        assert "/api/data" in data.links
        assert "/detail" in data.links

    def test_extract_onclick_urls(self):
        html = _html_page(
            '<button onclick="window.location=\'/redirect\'">Go</button>'
        )
        data = extract_page_data(html)
        assert "/redirect" in data.links

    def test_extract_meta_generator(self):
        html = (
            '<html><head>'
            '<meta name="generator" content="WordPress 6.5">'
            '</head><body></body></html>'
        )
        data = extract_page_data(html)
        assert data.meta.get("generator") == "WordPress 6.5"

    def test_malformed_html_tolerant(self):
        html = "<html><body><a href='/ok'>Link</a><div>Unclosed"
        data = extract_page_data(html)
        assert "/ok" in data.links

    def test_multiple_forms(self):
        html = _html_page(
            '<form action="/search" method="GET">'
            '  <input type="text" name="q">'
            '</form>'
            '<form action="/register" method="POST">'
            '  <input type="email" name="email">'
            '  <input type="text" name="username">'
            '</form>'
        )
        data = extract_page_data(html)
        assert len(data.forms) == 2

    def test_field_classification_in_form(self):
        html = _html_page(
            '<form action="/search" method="GET">'
            '  <input type="text" name="q">'
            '  <input type="hidden" name="redirect">'
            '  <input type="file" name="upload">'
            '</form>'
        )
        data = extract_page_data(html)
        fields = data.forms[0]["fields"]
        q_field = [f for f in fields if f["name"] == "q"][0]
        assert q_field["classification"] == "search_field"
        redir_field = [f for f in fields if f["name"] == "redirect"][0]
        assert redir_field["classification"] == "url_field"
        upload_field = [f for f in fields if f["name"] == "upload"][0]
        assert upload_field["classification"] == "file_field"


class TestFingerprinting:
    def test_detect_nginx(self):
        result = fingerprint_technology(
            {"server": "nginx/1.24.0"}, "", ""
        )
        assert "Nginx" in result["server"]

    def test_detect_apache(self):
        result = fingerprint_technology(
            {"server": "Apache/2.4.58"}, "", ""
        )
        assert "Apache" in result["server"]

    def test_detect_php_cookie(self):
        result = fingerprint_technology(
            {"set-cookie": "PHPSESSID=abc123"}, "", ""
        )
        assert "PHP" in result["framework"]

    def test_detect_wordpress(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/style.css">'
        result = fingerprint_technology({}, html, "")
        assert "WordPress" in result["cms"]

    def test_detect_django_csrf(self):
        result = fingerprint_technology(
            {"set-cookie": "csrftoken=xyz"}, "", ""
        )
        assert "Django" in result["framework"]

    def test_detect_cloudflare(self):
        result = fingerprint_technology(
            {"server": "cloudflare"}, "", ""
        )
        assert "Cloudflare" in result["server"]

    def test_no_fingerprint(self):
        result = fingerprint_technology({}, "<html></html>", "")
        assert result["server"] == []
        assert result["framework"] == []
        assert result["cms"] == []

    def test_detect_express(self):
        result = fingerprint_technology(
            {"x-powered-by": "Express"}, "", ""
        )
        assert "Express" in result["framework"]


class TestIsHtmlContent:
    def test_html(self):
        assert _is_html_content("text/html; charset=utf-8") is True

    def test_xhtml(self):
        assert _is_html_content("application/xhtml+xml") is True

    def test_json(self):
        assert _is_html_content("application/json") is False

    def test_empty(self):
        assert _is_html_content("") is True  # assume HTML if no CT


# ══════════════════════════════════════════════════════════════════
#  Integration tests — async crawl with mocked HTTP
# ══════════════════════════════════════════════════════════════════


@pytest.fixture
def config():
    return _make_config()


class TestHttpCrawlerIntegration:
    """Full crawler tests with respx-mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_basic_crawl_single_page(self, config):
        """Crawl a single page with no outgoing links."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Hello world</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            assert len(endpoints) >= 1
            assert any(ep.url.rstrip("/") == "https://example.com" for ep in endpoints)

    @pytest.mark.asyncio
    async def test_crawl_follows_links(self, config):
        """Crawler discovers linked pages within depth limit."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/about">About</a>'
                        '<a href="/contact">Contact</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/about").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>About page</p>"),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/contact").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Contact page</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert any("about" in u for u in urls)
            assert any("contact" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_extracts_forms(self, config):
        """Crawler discovers form endpoints."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<form action="/login" method="POST">'
                        '  <input type="text" name="username">'
                        '  <input type="password" name="password">'
                        '</form>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            form_eps = [ep for ep in endpoints if ep.method == "POST"]
            assert len(form_eps) >= 1
            login_ep = form_eps[0]
            assert "login" in login_ep.url
            field_names = [f.get("name") for f in login_ep.forms]
            assert "username" in field_names
            assert "password" in field_names

    @pytest.mark.asyncio
    async def test_crawl_respects_depth(self):
        """Crawler stops at max_depth."""
        config = _make_config(depth=1)

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page('<a href="/page1">Page 1</a>'),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/page1").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page('<a href="/page2">Page 2</a>'),
                    headers={"content-type": "text/html"},
                )
            )
            # page2 should NOT be fetched at depth=1
            page2_route = respx_mock.get("https://example.com/page2").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Deep page</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert any("page1" in u for u in urls)
            # page2 should NOT be visited (depth=1 means: root + 1 level)
            assert not any("page2" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_skips_external_links(self, config):
        """Crawler does not follow links to other domains."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="https://evil.com/steal">Evil</a>'
                        '<a href="/internal">Internal</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/internal").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Internal</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert not any("evil.com" in u for u in urls)
            assert any("internal" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_skips_static_assets(self, config):
        """Crawler skips links to images, CSS, fonts, etc."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/style.css">CSS</a>'
                        '<a href="/logo.png">Logo</a>'
                        '<a href="/doc.pdf">PDF</a>'
                        '<a href="/page">Page</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/page").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>A page</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert not any(".css" in u for u in urls)
            assert not any(".png" in u for u in urls)
            assert not any(".pdf" in u for u in urls)
            assert any("page" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_deduplicates(self, config):
        """Crawler does not visit the same URL twice."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/dup">Link 1</a>'
                        '<a href="/dup">Link 2</a>'
                        '<a href="/dup/">Link 3 trailing slash</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            dup_route = respx_mock.get("https://example.com/dup").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Dup page</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            # /dup should only appear once as an endpoint
            dup_eps = [ep for ep in endpoints if "dup" in ep.url]
            assert len(dup_eps) == 1

    @pytest.mark.asyncio
    async def test_crawl_robots_txt_respected(self):
        """Crawler skips paths disallowed by robots.txt."""
        config = _make_config()

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(
                    200,
                    text="User-agent: *\nDisallow: /admin/\n",
                    headers={"content-type": "text/plain"},
                )
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/admin/panel">Admin</a>'
                        '<a href="/public">Public</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            admin_route = respx_mock.get("https://example.com/admin/panel").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Admin panel</p>"),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/public").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Public</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert not any("admin" in u for u in urls)
            assert any("public" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_ignore_robots(self):
        """With ignore_robots=True, crawler visits disallowed paths."""
        config = _make_config()

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(
                    200,
                    text="User-agent: *\nDisallow: /secret/\n",
                    headers={"content-type": "text/plain"},
                )
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page('<a href="/secret/data">Secret</a>'),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/secret/data").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Top secret</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(
                    config=config, http_client=client, ignore_robots=True
                )
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert any("secret" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_fingerprinting(self, config):
        """Crawler detects technology from response headers."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Hello</p>"),
                    headers={
                        "content-type": "text/html",
                        "server": "nginx/1.25.0",
                        "x-powered-by": "Express",
                    },
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                await crawler.crawl("https://example.com")

            assert "Nginx" in crawler.technology.get("server", [])
            assert "Express" in crawler.technology.get("framework", [])

    @pytest.mark.asyncio
    async def test_crawl_handles_429(self, config):
        """Crawler handles 429 rate limiting without crashing."""
        call_count = 0

        def _side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return httpx.Response(429, text="Rate limited")
            return httpx.Response(
                200,
                text=_html_page("<p>OK</p>"),
                headers={"content-type": "text/html"},
            )

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(side_effect=_side_effect)

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            assert len(endpoints) >= 1

    @pytest.mark.asyncio
    async def test_crawl_handles_connection_error(self, config):
        """Crawler gracefully handles connection errors."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page('<a href="/broken">Broken</a>'),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/broken").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            # Should complete without raising, root page still discovered
            assert len(endpoints) >= 1

    @pytest.mark.asyncio
    async def test_crawl_url_found_callback(self, config):
        """on_url_found callbacks are invoked for discovered URLs."""
        discovered: list[str] = []

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page('<a href="/new-page">New</a>'),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/new-page").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>New page</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                crawler.on_url_found(lambda url: discovered.append(url))
                await crawler.crawl("https://example.com")

            assert len(discovered) >= 1
            assert any("new-page" in u for u in discovered)

    @pytest.mark.asyncio
    async def test_crawl_with_query_params(self, config):
        """Crawler captures query parameters as endpoint params."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/search?q=test&page=1">Search</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/search").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Results</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            search_eps = [ep for ep in endpoints if "search" in ep.url]
            assert len(search_eps) >= 1
            ep = search_eps[0]
            assert "q" in ep.params or "page" in ep.params

    @pytest.mark.asyncio
    async def test_crawl_exclude_pattern(self):
        """Crawler skips URLs matching exclude_patterns."""
        config = _make_config(exclude_patterns=[r"/logout"])

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page(
                        '<a href="/logout">Logout</a>'
                        '<a href="/dashboard">Dashboard</a>'
                    ),
                    headers={"content-type": "text/html"},
                )
            )
            respx_mock.get("https://example.com/dashboard").mock(
                return_value=httpx.Response(
                    200,
                    text=_html_page("<p>Dashboard</p>"),
                    headers={"content-type": "text/html"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            urls = {ep.url for ep in endpoints}
            assert not any("logout" in u for u in urls)
            assert any("dashboard" in u for u in urls)

    @pytest.mark.asyncio
    async def test_crawl_non_html_response_skipped(self, config):
        """Crawler skips non-HTML responses (JSON API, etc.)."""
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx_mock.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    text='{"status": "ok"}',
                    headers={"content-type": "application/json"},
                )
            )

            async with HttpClient(timeout=5, verify_ssl=False) as client:
                crawler = HttpCrawler(config=config, http_client=client)
                endpoints = await crawler.crawl("https://example.com")

            # No endpoints for JSON response (no HTML to parse)
            assert len(endpoints) == 0
