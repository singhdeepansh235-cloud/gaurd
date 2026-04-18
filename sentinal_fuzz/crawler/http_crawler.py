"""HTTP crawler for Sentinal-Fuzz — static website crawler.

Performs async breadth-first crawling of static (non-JS-rendered) websites.
Discovers URLs, forms, input fields, and performs basic technology
fingerprinting.

Usage::

    from sentinal_fuzz.crawler.http_crawler import HttpCrawler

    crawler = HttpCrawler(config=scan_config, http_client=client)
    endpoints = await crawler.crawl("https://example.com")
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from sentinal_fuzz.core.models import Endpoint
from sentinal_fuzz.crawler.base import BaseCrawler
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient, Response

log = get_logger("http_crawler")

# ── Static asset extensions to skip ───────────────────────────────
_STATIC_EXTENSIONS: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dmg", ".deb", ".rpm", ".msi", ".apk",
    ".map", ".wasm",
})

# ── Input-field classification patterns ───────────────────────────
_FIELD_CLASSIFIERS: list[tuple[str, re.Pattern[str]]] = [
    ("id_field",     re.compile(r"(?:^id$|uid|user_id|userId|_id$)", re.I)),
    ("search_field", re.compile(r"(?:^q$|query|search|keyword|term)", re.I)),
    ("url_field",    re.compile(r"(?:url|redirect|next|return|goto|dest|link|ref)", re.I)),
    ("file_field",   re.compile(r"^__FILE_TYPE__$")),  # matched by type, not name
    ("email_field",  re.compile(r"^__EMAIL_TYPE__$")),  # matched by type, not name
]


def classify_field(name: str, field_type: str) -> str:
    """Classify an input field by its name/type for fuzzer targeting.

    Returns one of: id_field, search_field, url_field, file_field,
    email_field, or generic_text.
    """
    if field_type == "file":
        return "file_field"
    if field_type == "email":
        return "email_field"
    for label, pattern in _FIELD_CLASSIFIERS:
        if label.startswith("__"):
            continue
        if pattern.search(name):
            return label
    return "generic_text"


# ── robots.txt parser ─────────────────────────────────────────────

@dataclass
class RobotsRules:
    """Parsed robots.txt Disallow/Allow rules for the User-agent: * block."""
    disallowed: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)

    def is_allowed(self, path: str) -> bool:
        """Check if a path is allowed (most-specific rule wins)."""
        # Explicit allows override disallows (most-specific first)
        best_disallow = ""
        best_allow = ""
        for d in self.disallowed:
            if path.startswith(d) and len(d) > len(best_disallow):
                best_disallow = d
        for a in self.allowed:
            if path.startswith(a) and len(a) > len(best_allow):
                best_allow = a

        if not best_disallow:
            return True
        return len(best_allow) > len(best_disallow)


def parse_robots_txt(body: str) -> RobotsRules:
    """Parse a robots.txt body and extract rules for User-agent: *."""
    rules = RobotsRules()
    active = False  # whether we're inside a User-agent: * block

    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            active = value == "*"
        elif key == "sitemap":
            rules.sitemaps.append(value)
        elif active:
            if key == "disallow" and value:
                rules.disallowed.append(value)
            elif key == "allow" and value:
                rules.allowed.append(value)

    return rules


# ── HTML link/form extractor (stdlib — no lxml dependency) ────────

@dataclass
class _ExtractedData:
    """All data extracted from a single HTML page."""
    links: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    link_hrefs: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)


class _HtmlExtractor(HTMLParser):
    """Fast, single-pass HTML parser that extracts links, forms, and metadata."""

    def __init__(self) -> None:
        super().__init__()
        self.data = _ExtractedData()
        self._in_form = False
        self._current_form: dict[str, Any] = {}
        self._current_fields: list[dict[str, str]] = []
        self._in_select = False
        self._current_select_name = ""
        self._current_select_options: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map: dict[str, str] = {
            k: (v or "") for k, v in attrs
        }

        # ── <a href> ──────────────────────────────────────────────
        if tag == "a":
            href = attr_map.get("href", "")
            if href:
                self.data.links.append(href)

        # ── <script src> ──────────────────────────────────────────
        elif tag == "script":
            src = attr_map.get("src", "")
            if src:
                self.data.script_srcs.append(src)

        # ── <link href> ──────────────────────────────────────────
        elif tag == "link":
            href = attr_map.get("href", "")
            if href:
                self.data.link_hrefs.append(href)

        # ── <meta name content / generator> ──────────────────────
        elif tag == "meta":
            name = attr_map.get("name", "").lower()
            content = attr_map.get("content", "")
            if name and content:
                self.data.meta[name] = content

        # ── <img> — skip but could be a link ─────────────────────
        elif tag == "img":
            pass

        # ── <form> ────────────────────────────────────────────────
        elif tag == "form":
            self._in_form = True
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "GET").upper(),
                "enctype": attr_map.get("enctype", ""),
            }
            self._current_fields = []

        # ── <input> ───────────────────────────────────────────────
        elif tag == "input" and self._in_form:
            input_type = attr_map.get("type", "text").lower()
            name = attr_map.get("name", "")
            value = attr_map.get("value", "")
            if name:
                self._current_fields.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                    "classification": classify_field(name, input_type),
                })

        # ── <textarea> ────────────────────────────────────────────
        elif tag == "textarea" and self._in_form:
            name = attr_map.get("name", "")
            if name:
                self._current_fields.append({
                    "name": name,
                    "type": "textarea",
                    "value": "",
                    "classification": classify_field(name, "textarea"),
                })

        # ── <select> ──────────────────────────────────────────────
        elif tag == "select" and self._in_form:
            self._in_select = True
            self._current_select_name = attr_map.get("name", "")
            self._current_select_options = []

        # ── <option> ──────────────────────────────────────────────
        elif tag == "option" and self._in_select:
            val = attr_map.get("value", "")
            if val:
                self._current_select_options.append(val)

        # ── <button type="submit"> ────────────────────────────────
        elif tag == "button" and self._in_form:
            btn_type = attr_map.get("type", "").lower()
            name = attr_map.get("name", "")
            value = attr_map.get("value", "")
            if btn_type == "submit" and name:
                self._current_fields.append({
                    "name": name,
                    "type": "submit",
                    "value": value,
                    "classification": "generic_text",
                })

        # ── data-url / data-href / data-action attributes ────────
        for dattr in ("data-url", "data-href", "data-action"):
            dval = attr_map.get(dattr, "")
            if dval and dval.startswith(("http://", "https://", "/")):
                self.data.links.append(dval)

        # ── onclick containing URLs ──────────────────────────────
        onclick = attr_map.get("onclick", "")
        if onclick:
            # Extract quoted URLs from onclick handlers
            for match in re.finditer(
                r"""(?:window\.location|location\.href)\s*=\s*['"]([^'"]+)['"]""",
                onclick,
            ):
                self.data.links.append(match.group(1))
            for match in re.finditer(r"""['"](\/?[a-zA-Z0-9._/-]+\?[^'"]+)['"]""", onclick):
                self.data.links.append(match.group(1))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            self._in_form = False
            self._current_form["fields"] = self._current_fields
            self.data.forms.append(self._current_form)
            self._current_form = {}
            self._current_fields = []

        elif tag == "select" and self._in_select:
            self._in_select = False
            if self._current_select_name:
                self._current_fields.append({
                    "name": self._current_select_name,
                    "type": "select",
                    "value": self._current_select_options[0] if self._current_select_options else "",
                    "options": self._current_select_options,
                    "classification": classify_field(self._current_select_name, "select"),
                })

    def handle_data(self, data: str) -> None:
        pass

    def error(self, message: str) -> None:  # type: ignore[override]
        pass  # Swallow HTML parse errors


def extract_page_data(html: str) -> _ExtractedData:
    """Parse HTML and extract all links, forms, and metadata."""
    parser = _HtmlExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass  # Tolerate malformed HTML
    return parser.data


# ── Technology fingerprinting ─────────────────────────────────────

_SERVER_PATTERNS: list[tuple[str, str]] = [
    ("Apache",     r"(?i)apache"),
    ("Nginx",      r"(?i)nginx"),
    ("IIS",        r"(?i)microsoft-iis"),
    ("Cloudflare", r"(?i)cloudflare"),
    ("LiteSpeed",  r"(?i)litespeed"),
]

_FRAMEWORK_PATTERNS: list[tuple[str, str]] = [
    ("ASP.NET",      r"(?i)asp\.net"),
    ("PHP",          r"(?i)php"),
    ("Express",      r"(?i)express"),
    ("Django",       r"(?i)django|csrfmiddlewaretoken"),
    ("Rails",        r"(?i)phusion|x-powered-by:\s*phusion|rails"),
    ("Spring",       r"(?i)spring"),
    ("Laravel",      r"(?i)laravel"),
    ("Flask",        r"(?i)werkzeug"),
]

_CMS_PATTERNS: list[tuple[str, str]] = [
    ("WordPress",  r"(?i)wp-content|wp-includes|wordpress"),
    ("Drupal",     r"(?i)drupal|sites/default/files"),
    ("Joomla",     r"(?i)joomla|/administrator/"),
    ("Magento",    r"(?i)magento|/skin/frontend/"),
    ("Shopify",    r"(?i)shopify|cdn\.shopify\.com"),
]


def fingerprint_technology(
    headers: dict[str, str],
    body: str,
    url: str,
) -> dict[str, list[str]]:
    """Detect server, framework, and CMS from response data.

    Returns dict with keys 'server', 'framework', 'cms', each a list
    of detected technology names.
    """
    results: dict[str, list[str]] = {
        "server": [],
        "framework": [],
        "cms": [],
    }

    # ── Headers ────────────────────────────────────────────────────
    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    combined_headers = f"{server_header} {powered_by}"

    for tech_name, pattern in _SERVER_PATTERNS:
        if re.search(pattern, combined_headers):
            results["server"].append(tech_name)

    for tech_name, pattern in _FRAMEWORK_PATTERNS:
        if re.search(pattern, combined_headers):
            results["framework"].append(tech_name)

    # ── Cookie names ───────────────────────────────────────────────
    set_cookie = headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        if "PHP" not in results["framework"]:
            results["framework"].append("PHP")
    if "JSESSIONID" in set_cookie:
        if "Java/Servlet" not in results["framework"]:
            results["framework"].append("Java/Servlet")
    if "ASP.NET_SessionId" in set_cookie:
        if "ASP.NET" not in results["framework"]:
            results["framework"].append("ASP.NET")
    if "csrftoken" in set_cookie.lower():
        if "Django" not in results["framework"]:
            results["framework"].append("Django")
    if "laravel_session" in set_cookie.lower():
        if "Laravel" not in results["framework"]:
            results["framework"].append("Laravel")

    # ── Body + URL ─────────────────────────────────────────────────
    combined_text = f"{body} {url}"
    for tech_name, pattern in _CMS_PATTERNS:
        if re.search(pattern, combined_text):
            results["cms"].append(tech_name)

    # ── Meta generator ─────────────────────────────────────────────
    gen_match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
        body, re.I,
    )
    if gen_match:
        gen = gen_match.group(1)
        for tech_name, pattern in _CMS_PATTERNS:
            if re.search(pattern, gen, re.I):
                if tech_name not in results["cms"]:
                    results["cms"].append(tech_name)
        for tech_name, pattern in _FRAMEWORK_PATTERNS:
            if re.search(pattern, gen, re.I):
                if tech_name not in results["framework"]:
                    results["framework"].append(tech_name)

    return results


# ══════════════════════════════════════════════════════════════════
#  Main crawler class
# ══════════════════════════════════════════════════════════════════

class HttpCrawler(BaseCrawler):
    """Async BFS crawler for static websites.

    Discovers endpoints by following links, extracting forms, and
    analysing response data.  Respects ``max_depth``, domain scope,
    and ``robots.txt``.

    Usage::

        async with HttpClient(timeout=10) as client:
            crawler = HttpCrawler(config=cfg, http_client=client)
            endpoints = await crawler.crawl("https://example.com")
    """

    def __init__(
        self,
        config: ScanConfig,
        http_client: HttpClient,
        *,
        ignore_robots: bool = False,
    ) -> None:
        super().__init__(config, http_client)
        self.ignore_robots = ignore_robots
        self.robots: RobotsRules | None = None
        self.technology: dict[str, list[str]] = {}
        self._rate_semaphore: asyncio.Semaphore | None = None

        # Queue holds (url, depth) tuples
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._seen_urls: set[str] = set()

    # ── Public API ─────────────────────────────────────────────────

    async def crawl(self, url: str) -> list[Endpoint]:
        """BFS crawl starting from *url*.

        Returns all discovered ``Endpoint`` objects.
        """
        log.info("Starting HTTP crawl: %s (depth=%d)", url, self.config.depth)

        # Concurrency limiter
        self._rate_semaphore = asyncio.Semaphore(self.config.concurrency)

        # Fetch robots.txt
        if not self.ignore_robots:
            await self._fetch_robots(url)

        # Seed the queue
        norm = self.normalize_url(url)
        self._seen_urls.add(norm)
        await self._queue.put((norm, 0))
        self.state.mark_visited(norm, 0)

        # Launch worker pool
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(min(self.config.concurrency, 20))
        ]

        # Wait for queue to drain
        await self._queue.join()

        # Cancel workers
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        log.info(
            "Crawl complete: %d endpoints, %d URLs visited, %d errors",
            len(self.state.endpoints),
            len(self.state.visited),
            len(self.state.errors),
        )

        return self.state.endpoints

    # ── BFS worker ─────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        """Consumer coroutine that processes URLs from the queue."""
        while True:
            try:
                url, depth = await self._queue.get()
            except asyncio.CancelledError:
                return

            try:
                assert self._rate_semaphore is not None
                async with self._rate_semaphore:
                    await self._process_url(url, depth)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                self.state.errors[url] = str(exc)
                log.warning("Worker %d error on %s: %s", worker_id, url, exc)
            finally:
                self._queue.task_done()

    async def _process_url(self, url: str, depth: int) -> None:
        """Fetch a URL, extract data, and enqueue discovered links."""
        # robots.txt check
        if self.robots and not self.ignore_robots:
            path = urlparse(url).path
            if not self.robots.is_allowed(path):
                log.debug("Blocked by robots.txt: %s", url)
                return

        # Fetch
        try:
            response = await self._safe_fetch(url)
        except Exception as exc:
            self.state.errors[url] = str(exc)
            log.debug("Fetch failed for %s: %s", url, exc)
            return

        if response is None:
            return

        # Content-type check — only parse HTML
        content_type = response.headers.get("content-type", "")
        if not _is_html_content(content_type):
            return

        # Technology fingerprinting (on first page)
        if not self.technology:
            self.technology = fingerprint_technology(
                response.headers, response.text, url,
            )
            if self.technology.get("server") or self.technology.get("framework"):
                log.info("Detected tech: %s", self.technology)

        # Parse HTML
        page_data = extract_page_data(response.text)

        # Create endpoint for this page
        parsed = urlparse(url)
        query_params = dict(parse_qsl(parsed.query))
        page_endpoint = Endpoint(
            url=url,
            method="GET",
            params=query_params,
            source="crawl",
        )

        # Add form endpoints
        for form_data in page_data.forms:
            form_endpoint = self._build_form_endpoint(url, form_data)
            if form_endpoint:
                self._add_endpoint(form_endpoint)

        self._add_endpoint(page_endpoint)

        # Enqueue discovered links if within depth limit
        if depth < self.config.depth:
            all_links = (
                page_data.links
                + page_data.link_hrefs
            )
            for raw_link in all_links:
                resolved = self._resolve_url(raw_link, url)
                if resolved:
                    norm = self.normalize_url(resolved)
                    if self._should_enqueue(norm):
                        self._seen_urls.add(norm)
                        self.state.mark_visited(norm, depth + 1)
                        await self._queue.put((norm, depth + 1))
                        self._notify_url_found(norm)

    # ── HTTP fetch with error handling ────────────────────────────

    async def _safe_fetch(self, url: str) -> Response | None:
        """Fetch a URL with retries and rate-limit backoff.

        Handles 429, connection errors, and SSL failures gracefully.
        Returns None if the URL cannot be fetched.
        """
        import httpx

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = await self.http_client.get(url)

                # 429 Too Many Requests — backoff and retry
                if response.status_code == 429:
                    if attempt < max_attempts:
                        wait = 5 * attempt
                        log.warning(
                            "Rate limited (429) on %s — backing off %ds",
                            url, wait,
                        )
                        await asyncio.sleep(wait)
                        continue
                    else:
                        log.warning("Rate limited (429) on %s — giving up", url)
                        return None

                return response

            except httpx.HTTPError as exc:
                if attempt < max_attempts:
                    log.debug(
                        "Fetch attempt %d/%d failed for %s: %s",
                        attempt, max_attempts, url, exc,
                    )
                    await asyncio.sleep(1)
                else:
                    log.warning("All fetch attempts failed for %s: %s", url, exc)
                    return None

        return None  # pragma: no cover

    # ── robots.txt ────────────────────────────────────────────────

    async def _fetch_robots(self, base_url: str) -> None:
        """Fetch and parse robots.txt for the target domain."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            response = await self.http_client.get(robots_url)
            if response.status_code == 200:
                self.robots = parse_robots_txt(response.text)
                log.info(
                    "robots.txt: %d disallow rules, %d sitemaps",
                    len(self.robots.disallowed),
                    len(self.robots.sitemaps),
                )
            else:
                log.debug("No robots.txt (status %d)", response.status_code)
        except Exception as exc:
            log.debug("Failed to fetch robots.txt: %s", exc)

    # ── URL helpers ───────────────────────────────────────────────

    def _resolve_url(self, raw: str, base_url: str) -> str | None:
        """Resolve a raw href/action against a base URL.

        Returns the absolute URL if valid, or None if it should be skipped.
        """
        raw = raw.strip()

        # Skip non-http schemes
        if raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "{{", "{")):
            return None

        # Resolve relative URLs
        absolute = urljoin(base_url, raw)

        # Only allow http/https
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return None

        # Skip static assets
        path_lower = parsed.path.lower()
        ext = ""
        if "." in path_lower.rsplit("/", 1)[-1]:
            ext = "." + path_lower.rsplit(".", 1)[-1]
        if ext in _STATIC_EXTENSIONS:
            return None

        return absolute

    def _should_enqueue(self, normalized_url: str) -> bool:
        """Check if a normalized URL should be added to the crawl queue."""
        # Already seen?
        if normalized_url in self._seen_urls:
            return False

        # In scope?
        if not self.is_in_scope(normalized_url):
            return False

        return True

    # ── Form → Endpoint builder ───────────────────────────────────

    def _build_form_endpoint(
        self, page_url: str, form_data: dict[str, Any]
    ) -> Endpoint | None:
        """Convert extracted form data into an ``Endpoint`` object."""
        action = form_data.get("action", "")
        method = form_data.get("method", "GET").upper()
        fields: list[dict[str, str]] = form_data.get("fields", [])

        # Resolve form action URL
        if action:
            resolved = self._resolve_url(action, page_url)
            if not resolved:
                return None
            action_url = resolved
        else:
            action_url = page_url  # form submits to itself

        action_url = self.normalize_url(action_url)

        # Build params from form fields
        params: dict[str, str] = {}
        form_fields: list[dict[str, str]] = []

        for fld in fields:
            form_fields.append({
                "name": fld.get("name", ""),
                "type": fld.get("type", "text"),
                "value": fld.get("value", ""),
                "classification": fld.get("classification", "generic_text"),
            })
            if method == "GET":
                params[fld["name"]] = fld.get("value", "")

        return Endpoint(
            url=action_url,
            method=method,
            params=params if method == "GET" else {},
            forms=form_fields,
            source="form",
        )

    # ── Endpoint dedup + add ──────────────────────────────────────

    def _add_endpoint(self, endpoint: Endpoint) -> None:
        """Add an endpoint to state if not a duplicate."""
        # Simple dedup: (url, method) pair
        for existing in self.state.endpoints:
            if existing.url == endpoint.url and existing.method == endpoint.method:
                # Merge forms
                if endpoint.forms:
                    existing_names = {
                        f.get("name") for f in existing.forms
                    }
                    for f in endpoint.forms:
                        if f.get("name") not in existing_names:
                            existing.forms.append(f)
                # Merge params
                for k, v in endpoint.params.items():
                    if k not in existing.params:
                        existing.params[k] = v
                return

        self.state.endpoints.append(endpoint)


# ── Utilities ─────────────────────────────────────────────────────

def _is_html_content(content_type: str) -> bool:
    """Check if Content-Type indicates HTML."""
    ct = content_type.lower()
    return "text/html" in ct or "application/xhtml" in ct or not ct
