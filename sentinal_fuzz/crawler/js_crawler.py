"""Playwright-based JavaScript crawler for Sentinal-Fuzz.

Extends the static HTTP crawler with real browser execution to discover
endpoints rendered by JavaScript frameworks (React, Angular, Vue, Next.js,
Nuxt...).  Falls back to ``HttpCrawler`` when Playwright is unavailable.

Usage::

    from sentinal_fuzz.crawler.js_crawler import JsCrawler

    crawler = JsCrawler(config=scan_config, http_client=client)
    endpoints = await crawler.crawl("https://example.com")
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from sentinal_fuzz.core.models import Endpoint
from sentinal_fuzz.crawler.base import BaseCrawler
from sentinal_fuzz.crawler.http_crawler import (
    classify_field,
    extract_page_data,
)
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient

log = get_logger("js_crawler")

# ── Probe values for form auto-fill ─────────────────────────────
_PROBE_VALUES: dict[str, str] = {
    "text": "test123",
    "search": "test123",
    "tel": "5551234567",
    "number": "1",
    "email": "test@example.com",
    "password": "Test123!@#",
    "url": "https://example.com",
    "textarea": "test123",
}

# ── User Agent ───────────────────────────────────────────────────
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# ── JS snippets ──────────────────────────────────────────────────

_JS_EXTRACT_LINKS = """
() => {
    const links = new Set();
    // All <a> hrefs
    document.querySelectorAll('a[href]').forEach(a => links.add(a.href));
    // data-url, data-href, data-action
    document.querySelectorAll('[data-url], [data-href], [data-action]').forEach(el => {
        ['data-url', 'data-href', 'data-action'].forEach(attr => {
            const v = el.getAttribute(attr);
            if (v) links.add(v);
        });
    });
    // Router links (vue-router, react-router)
    document.querySelectorAll('[to], [routerlink]').forEach(el => {
        const v = el.getAttribute('to') || el.getAttribute('routerlink');
        if (v) links.add(v);
    });
    return [...links];
}
"""

_JS_EXTRACT_FORMS = """
() => {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        const fields = [];
        form.querySelectorAll('input, select, textarea').forEach(el => {
            const name = el.name || el.id || '';
            if (!name) return;
            fields.push({
                name: name,
                type: el.type || el.tagName.toLowerCase(),
                value: el.value || '',
                tag: el.tagName.toLowerCase(),
            });
        });
        forms.push({
            action: form.action || '',
            method: (form.method || 'GET').toUpperCase(),
            fields: fields,
        });
    });
    return forms;
}
"""

_JS_EXTRACT_DYNAMIC_INPUTS = """
() => {
    const inputs = [];
    document.querySelectorAll('input, select, textarea').forEach(el => {
        const name = el.name || el.id || '';
        if (!name) return;
        inputs.push({
            name: name,
            type: el.type || el.tagName.toLowerCase(),
            value: el.value || '',
            formAction: el.form ? (el.form.action || '') : '',
            formMethod: el.form ? (el.form.method || 'GET').toUpperCase() : 'GET',
        });
    });
    return inputs;
}
"""

_JS_EXTRACT_SPA_ROUTES = """
() => {
    const routes = {};

    // Next.js
    try {
        if (window.__NEXT_DATA__) {
            routes.nextjs = JSON.stringify(window.__NEXT_DATA__);
        }
    } catch(e) {}

    // Nuxt.js
    try {
        if (window.__NUXT__) {
            routes.nuxtjs = JSON.stringify(window.__NUXT__);
        }
    } catch(e) {}

    // Angular routes (common patterns)
    try {
        if (window.ANGULAR_ROUTES) {
            routes.angular = JSON.stringify(window.ANGULAR_ROUTES);
        }
    } catch(e) {}

    // Scan all string variables for /api/ patterns
    try {
        const apiEndpoints = [];
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
            const text = script.textContent || '';
            const matches = text.match(/["'](\\/api\\/[^"'\\s]+)["']/g);
            if (matches) {
                matches.forEach(m => {
                    apiEndpoints.push(m.replace(/["']/g, ''));
                });
            }
        });
        if (apiEndpoints.length > 0) {
            routes.api_from_js = apiEndpoints;
        }
    } catch(e) {}

    return routes;
}
"""

_JS_HOOK_PUSHSTATE = """
() => {
    window.__sentinalRoutes = window.__sentinalRoutes || [];
    const _pushState = history.pushState;
    const _replaceState = history.replaceState;
    history.pushState = function() {
        _pushState.apply(this, arguments);
        window.__sentinalRoutes.push(arguments[2]);
    };
    history.replaceState = function() {
        _replaceState.apply(this, arguments);
        window.__sentinalRoutes.push(arguments[2]);
    };
    window.addEventListener('hashchange', () => {
        window.__sentinalRoutes.push(location.hash);
    });
}
"""

_JS_GET_PUSHSTATE_ROUTES = """
() => {
    return window.__sentinalRoutes || [];
}
"""

_JS_GET_CLICKABLE = """
() => {
    const elements = [];
    // Buttons
    document.querySelectorAll('button, [role="button"], [role="link"]').forEach((el, i) => {
        elements.push({
            index: i,
            tag: el.tagName,
            text: (el.textContent || '').trim().substring(0, 50),
            type: el.getAttribute('type') || '',
        });
    });
    // Elements with onclick
    document.querySelectorAll('[onclick]').forEach((el, i) => {
        elements.push({
            index: 1000 + i,
            tag: el.tagName,
            text: (el.textContent || '').trim().substring(0, 50),
            type: 'onclick',
        });
    });
    return elements;
}
"""


class JsCrawler(BaseCrawler):
    """Playwright-based crawler that renders JavaScript and discovers
    dynamic routes, API endpoints, and SPA navigation.

    Extends ``BaseCrawler`` with real Chromium execution.  Requires
    Playwright browsers to be installed (``playwright install chromium``).

    Usage::

        async with HttpClient(timeout=10) as client:
            crawler = JsCrawler(config=cfg, http_client=client)
            endpoints = await crawler.crawl("https://example.com")
    """

    def __init__(
        self,
        config: ScanConfig,
        http_client: HttpClient,
    ) -> None:
        super().__init__(config, http_client)
        self._intercepted_requests: list[dict[str, Any]] = []
        self._js_errors: list[str] = []

    # ── Public API ─────────────────────────────────────────────────

    async def crawl(self, url: str) -> list[Endpoint]:
        """Crawl *url* using a headless Chromium browser.

        1. Navigates to each page
        2. Hooks pushState / hashchange for SPA detection
        3. Intercepts XHR/fetch requests
        4. Clicks interactive elements
        5. Extracts forms and inputs (including dynamically rendered)
        6. Extracts SPA framework routes (__NEXT_DATA__, __NUXT__, etc.)
        """
        from playwright.async_api import async_playwright

        log.info("Starting JS crawl: %s (depth=%d)", url, self.config.depth)

        async with async_playwright() as pw:
            browser_args: dict[str, Any] = {
                "headless": True,
            }
            if self.config.proxy:
                browser_args["proxy"] = {"server": self.config.proxy}

            browser = await pw.chromium.launch(**browser_args)
            try:
                context = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent=_BROWSER_UA,
                )

                # Inject auth cookie if configured
                if self.config.auth_cookie:
                    await self._inject_cookies(context, url)

                # BFS through pages
                pages_to_visit: list[tuple[str, int]] = [(url, 0)]
                visited: set[str] = set()

                while pages_to_visit:
                    page_url, depth = pages_to_visit.pop(0)
                    norm = self.normalize_url(page_url)

                    if norm in visited:
                        continue
                    if not self.is_in_scope(page_url):
                        continue

                    visited.add(norm)
                    self.state.mark_visited(norm, depth)

                    page = await context.new_page()
                    try:
                        discovered = await self._process_page(page, page_url)

                        # Enqueue discovered links if depth allows
                        if depth < self.config.depth:
                            for new_url in discovered:
                                new_norm = self.normalize_url(new_url)
                                if new_norm not in visited and self.is_in_scope(new_url):
                                    pages_to_visit.append((new_url, depth + 1))
                                    self._notify_url_found(new_url)

                    except Exception as exc:
                        self.state.errors[page_url] = str(exc)
                        log.warning("JS crawl error on %s: %s", page_url, exc)
                        if self.config.verbose:
                            await self._screenshot_on_error(page, page_url)
                    finally:
                        await page.close()

            finally:
                await browser.close()

        log.info(
            "JS crawl complete: %d endpoints, %d URLs visited, "
            "%d API calls intercepted, %d errors",
            len(self.state.endpoints),
            len(visited),
            len(self._intercepted_requests),
            len(self.state.errors),
        )

        return self.state.endpoints

    # ── Page processing ────────────────────────────────────────────

    async def _process_page(self, page: Any, url: str) -> list[str]:
        """Process a single page and return newly discovered URLs."""
        discovered_links: list[str] = []

        # Set up network interception
        intercepted: list[dict[str, Any]] = []
        page.on("request", lambda req: self._on_request(req, intercepted))

        # Capture JS errors
        page.on("pageerror", lambda exc: self._js_errors.append(str(exc)))

        # Hook pushState before navigation
        await page.add_init_script(_JS_HOOK_PUSHSTATE)

        # Navigate
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception as exc:
            log.warning("Navigation failed for %s: %s", url, exc)
            # Try with less strict wait
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                self.state.errors[url] = str(exc)
                return []

        # Wait a bit for any deferred JS
        await page.wait_for_timeout(500)

        # ── Step 1: Scroll to trigger lazy loading ────────────────
        await self._scroll_page(page)

        # ── Step 2: Extract links from rendered DOM ───────────────
        try:
            raw_links = await page.evaluate(_JS_EXTRACT_LINKS)
            for link in raw_links:
                resolved = self._resolve_link(link, url)
                if resolved:
                    discovered_links.append(resolved)
        except Exception as exc:
            log.debug("Link extraction failed on %s: %s", url, exc)

        # ── Step 3: Extract forms from rendered DOM ───────────────
        try:
            forms_data = await page.evaluate(_JS_EXTRACT_FORMS)
            for form in forms_data:
                ep = self._form_to_endpoint(form, url)
                if ep:
                    self._add_endpoint(ep)
        except Exception as exc:
            log.debug("Form extraction failed on %s: %s", url, exc)

        # ── Step 4: Click interactive elements ────────────────────
        click_links = await self._click_interactive_elements(page, url)
        discovered_links.extend(click_links)

        # ── Step 5: Extract dynamic inputs (appeared after clicks) ─
        try:
            dynamic_inputs = await page.evaluate(_JS_EXTRACT_DYNAMIC_INPUTS)
            for inp in dynamic_inputs:
                # These are standalone inputs, create endpoints
                form_action = inp.get("formAction", "") or url
                self._add_endpoint(Endpoint(
                    url=self.normalize_url(form_action),
                    method=inp.get("formMethod", "GET"),
                    forms=[{
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                        "classification": classify_field(
                            inp.get("name", ""), inp.get("type", "text")
                        ),
                    }],
                    source="js-dynamic",
                ))
        except Exception as exc:
            log.debug("Dynamic input extraction failed: %s", exc)

        # ── Step 6: SPA route extraction ──────────────────────────
        try:
            spa_routes = await page.evaluate(_JS_EXTRACT_SPA_ROUTES)
            spa_links = self._parse_spa_routes(spa_routes, url)
            discovered_links.extend(spa_links)
        except Exception as exc:
            log.debug("SPA route extraction failed: %s", exc)

        # ── Step 7: Get pushState collected routes ────────────────
        try:
            push_routes = await page.evaluate(_JS_GET_PUSHSTATE_ROUTES)
            for route in push_routes:
                if route:
                    resolved = self._resolve_link(str(route), url)
                    if resolved:
                        discovered_links.append(resolved)
        except Exception:
            pass

        # ── Step 8: Process intercepted network requests ──────────
        for req_data in intercepted:
            self._intercepted_requests.append(req_data)
            ep = self._network_request_to_endpoint(req_data, url)
            if ep:
                self._add_endpoint(ep)

        # ── Step 9: Auto-fill and submit forms ────────────────────
        await self._interact_with_forms(page, url)

        # Create endpoint for the page itself  
        from urllib.parse import parse_qsl
        parsed = urlparse(url)
        self._add_endpoint(Endpoint(
            url=self.normalize_url(url),
            method="GET",
            params=dict(parse_qsl(parsed.query)),
            source="js-crawl",
        ))

        # Collect hash routes
        current_url = page.url
        if "#" in current_url:
            hash_part = current_url.split("#", 1)[1]
            if hash_part.startswith("/"):
                discovered_links.append(current_url)

        return list(set(discovered_links))

    # ── Browser interactions ──────────────────────────────────────

    async def _scroll_page(self, page: Any) -> None:
        """Scroll to the bottom of the page to trigger lazy loading."""
        try:
            await page.evaluate("""
                async () => {
                    const delay = (ms) => new Promise(r => setTimeout(r, ms));
                    const height = () => document.body.scrollHeight;
                    let lastHeight = 0;
                    let attempts = 0;
                    while (height() > lastHeight && attempts < 10) {
                        lastHeight = height();
                        window.scrollTo(0, height());
                        await delay(300);
                        attempts++;
                    }
                }
            """)
        except Exception:
            pass

    async def _click_interactive_elements(
        self, page: Any, base_url: str
    ) -> list[str]:
        """Click buttons and interactive elements, collect new links."""
        discovered: list[str] = []

        try:
            clickables = await page.evaluate(_JS_GET_CLICKABLE)
        except Exception:
            return discovered

        base_domain = urlparse(base_url).netloc

        for item in clickables[:20]:  # Limit to 20 clicks per page
            try:
                # Skip submit buttons (handled separately in form interaction)
                if item.get("type") == "submit":
                    continue

                # Find the element to click
                tag = item.get("tag", "").lower()
                text = item.get("text", "")

                if not text:
                    continue

                selector = None
                if item.get("type") == "onclick":
                    selector = f"[onclick]:has-text('{text[:20]}')"
                elif tag == "button":
                    selector = f"button:has-text('{text[:20]}')"
                else:
                    selector = f"[role='button']:has-text('{text[:20]}')"

                if not selector:
                    continue

                # Get URL before click
                url_before = page.url

                # Click with short timeout
                locator = page.locator(selector).first
                if await locator.count() == 0:
                    continue

                await locator.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(500)

                # Collect new URL if changed
                url_after = page.url
                if url_after != url_before:
                    after_domain = urlparse(url_after).netloc
                    if after_domain == base_domain:
                        discovered.append(url_after)
                    # Navigate back
                    try:
                        await page.go_back(wait_until="domcontentloaded", timeout=5000)
                    except Exception:
                        pass

                # Extract any new links that appeared
                try:
                    new_links = await page.evaluate(_JS_EXTRACT_LINKS)
                    for link in new_links:
                        resolved = self._resolve_link(link, base_url)
                        if resolved and resolved not in discovered:
                            discovered.append(resolved)
                except Exception:
                    pass

            except Exception:
                continue  # Individual click failures are not critical

        return discovered

    async def _interact_with_forms(self, page: Any, base_url: str) -> None:
        """Fill and submit forms to discover endpoints via actual requests."""
        try:
            forms = await page.evaluate(_JS_EXTRACT_FORMS)
        except Exception:
            return

        for form_data in forms[:5]:  # Limit to 5 forms per page
            try:
                fields = form_data.get("fields", [])

                for field in fields:
                    name = field.get("name", "")
                    field_type = field.get("type", "text").lower()
                    if not name:
                        continue

                    probe = _PROBE_VALUES.get(field_type, "test123")

                    try:
                        input_sel = f"[name='{name}']"
                        locator = page.locator(input_sel).first
                        if await locator.count() > 0:
                            if field_type == "select":
                                # Select first option
                                options = await locator.locator("option").all_text_contents()
                                if options:
                                    await locator.select_option(label=options[0])
                            elif field_type in ("checkbox", "radio"):
                                await locator.check()
                            elif field_type != "hidden":
                                await locator.fill(probe)
                    except Exception:
                        continue

                # Brief pause after filling
                await page.wait_for_timeout(200)

            except Exception:
                continue

    # ── Network interception ──────────────────────────────────────

    def _on_request(self, request: Any, intercepted: list[dict[str, Any]]) -> None:
        """Capture XHR and fetch requests for API endpoint discovery."""
        try:
            resource_type = request.resource_type
            if resource_type in ("xhr", "fetch"):
                req_data = {
                    "url": request.url,
                    "method": request.method,
                    "resource_type": resource_type,
                    "headers": dict(request.headers) if request.headers else {},
                    "post_data": request.post_data,
                }
                intercepted.append(req_data)
                log.debug(
                    "Intercepted %s %s %s",
                    resource_type, request.method, request.url,
                )
        except Exception:
            pass

    def _network_request_to_endpoint(
        self, req_data: dict[str, Any], page_url: str
    ) -> Endpoint | None:
        """Convert an intercepted network request to an Endpoint."""
        req_url = req_data.get("url", "")
        if not req_url:
            return None

        # Only keep in-scope requests
        if not self.is_in_scope(req_url):
            return None

        method = req_data.get("method", "GET").upper()
        headers = req_data.get("headers", {})

        # Parse query params
        from urllib.parse import parse_qsl
        parsed = urlparse(req_url)
        params = dict(parse_qsl(parsed.query))

        # Parse POST body as params
        post_data = req_data.get("post_data", "")
        post_params: dict[str, str] = {}
        if post_data and method in ("POST", "PUT", "PATCH"):
            try:
                # Try JSON
                json_data = json.loads(post_data)
                if isinstance(json_data, dict):
                    post_params = {k: str(v) for k, v in json_data.items()}
            except (json.JSONDecodeError, TypeError):
                # Try form-encoded
                post_params = dict(parse_qsl(post_data))

        all_params = {**params, **post_params}

        return Endpoint(
            url=self.normalize_url(req_url.split("?")[0] if "?" in req_url else req_url),
            method=method,
            params=all_params,
            headers={k: v for k, v in headers.items()
                     if k.lower() in ("content-type", "authorization", "x-csrf-token")},
            source="js-api",
            is_api=True,
        )

    # ── Cookie injection ──────────────────────────────────────────

    async def _inject_cookies(self, context: Any, url: str) -> None:
        """Parse and inject auth cookies into the browser context."""
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        cookies = []
        for part in self.config.auth_cookie.split(";"):  # type: ignore[union-attr]
            part = part.strip()
            if "=" not in part:
                continue
            name, _, value = part.partition("=")
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "domain": domain,
                "path": "/",
                "httpOnly": False,
                "secure": parsed.scheme == "https",
            })

        if cookies:
            await context.add_cookies(cookies)
            log.debug("Injected %d auth cookies for %s", len(cookies), domain)

    # ── SPA route parsing ─────────────────────────────────────────

    def _parse_spa_routes(
        self, routes_data: dict[str, Any], base_url: str
    ) -> list[str]:
        """Extract URLs from SPA framework data structures."""
        links: list[str] = []

        # Next.js __NEXT_DATA__
        next_data = routes_data.get("nextjs", "")
        if next_data:
            try:
                data = json.loads(next_data)
                # Extract page routes
                if "page" in data:
                    links.append(urljoin(base_url, data["page"]))
                # Build ID contains route
                if "buildId" in data and "props" in data:
                    page_props = data.get("props", {}).get("pageProps", {})
                    if isinstance(page_props, dict):
                        for key in page_props:
                            if isinstance(page_props[key], str) and page_props[key].startswith("/"):
                                links.append(urljoin(base_url, page_props[key]))
            except (json.JSONDecodeError, TypeError):
                pass

        # Nuxt.js __NUXT__
        nuxt_data = routes_data.get("nuxtjs", "")
        if nuxt_data:
            try:
                data = json.loads(nuxt_data)
                if isinstance(data, dict):
                    # Extract route from state
                    route = data.get("state", {}).get("route", {})
                    if isinstance(route, dict) and "path" in route:
                        links.append(urljoin(base_url, route["path"]))
            except (json.JSONDecodeError, TypeError):
                pass

        # Angular routes
        angular_data = routes_data.get("angular", "")
        if angular_data:
            try:
                data = json.loads(angular_data)
                if isinstance(data, list):
                    for route in data:
                        if isinstance(route, str):
                            links.append(urljoin(base_url, route))
                        elif isinstance(route, dict) and "path" in route:
                            links.append(urljoin(base_url, route["path"]))
            except (json.JSONDecodeError, TypeError):
                pass

        # API endpoints extracted from inline scripts
        api_endpoints = routes_data.get("api_from_js", [])
        if isinstance(api_endpoints, list):
            for api_path in api_endpoints:
                links.append(urljoin(base_url, api_path))

        return [l for l in links if self.is_in_scope(l)]

    # ── URL helpers ───────────────────────────────────────────────

    def _resolve_link(self, raw: str, base_url: str) -> str | None:
        """Resolve and filter a raw URL string."""
        if not raw or not isinstance(raw, str):
            return None

        raw = raw.strip()
        if raw.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:")):
            return None

        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return None

        if not self.is_in_scope(absolute):
            return None

        return absolute

    # ── Endpoint dedup ────────────────────────────────────────────

    def _add_endpoint(self, endpoint: Endpoint) -> None:
        """Add endpoint with deduplication by (url, method)."""
        for existing in self.state.endpoints:
            if existing.url == endpoint.url and existing.method == endpoint.method:
                # Merge forms
                if endpoint.forms:
                    existing_names = {f.get("name") for f in existing.forms}
                    for f in endpoint.forms:
                        if f.get("name") not in existing_names:
                            existing.forms.append(f)
                # Merge params
                for k, v in endpoint.params.items():
                    if k not in existing.params:
                        existing.params[k] = v
                # Promote to API if either is API
                if endpoint.is_api:
                    existing.is_api = True
                return
        self.state.endpoints.append(endpoint)

    def _form_to_endpoint(
        self, form_data: dict[str, Any], page_url: str
    ) -> Endpoint | None:
        """Convert JS-extracted form data to an Endpoint."""
        action = form_data.get("action", "") or page_url
        method = form_data.get("method", "GET").upper()
        fields = form_data.get("fields", [])

        resolved = self._resolve_link(action, page_url)
        if not resolved:
            return None

        form_fields: list[dict[str, str]] = []
        params: dict[str, str] = {}

        for fld in fields:
            name = fld.get("name", "")
            ftype = fld.get("type", "text")
            form_fields.append({
                "name": name,
                "type": ftype,
                "value": fld.get("value", ""),
                "classification": classify_field(name, ftype),
            })
            if method == "GET" and name:
                params[name] = fld.get("value", "")

        return Endpoint(
            url=self.normalize_url(resolved),
            method=method,
            params=params if method == "GET" else {},
            forms=form_fields,
            source="js-form",
        )

    # ── Debug helpers ─────────────────────────────────────────────

    async def _screenshot_on_error(self, page: Any, url: str) -> None:
        """Save a screenshot when a page error occurs (verbose mode only)."""
        try:
            debug_dir = Path("debug/screenshots")
            debug_dir.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w.-]", "_", urlparse(url).path or "root")
            path = debug_dir / f"error_{safe_name}.png"
            await page.screenshot(path=str(path))
            log.info("Error screenshot saved: %s", path)
        except Exception as exc:
            log.debug("Failed to save screenshot: %s", exc)


# ── Merge utility (combine HttpCrawler + JsCrawler results) ──────

def merge_endpoints(
    http_endpoints: list[Endpoint],
    js_endpoints: list[Endpoint],
) -> list[Endpoint]:
    """Merge two Endpoint lists, deduplicating by (url, method).

    JS-discovered data is merged into HTTP-discovered endpoints where
    they overlap.  API endpoints from JS are always preserved.
    """
    merged: dict[tuple[str, str], Endpoint] = {}

    for ep in http_endpoints:
        key = (ep.url, ep.method)
        merged[key] = ep

    for ep in js_endpoints:
        key = (ep.url, ep.method)
        if key in merged:
            existing = merged[key]
            # Merge forms
            existing_names = {f.get("name") for f in existing.forms}
            for f in ep.forms:
                if f.get("name") not in existing_names:
                    existing.forms.append(f)
            # Merge params
            for k, v in ep.params.items():
                if k not in existing.params:
                    existing.params[k] = v
            if ep.is_api:
                existing.is_api = True
        else:
            merged[key] = ep

    return list(merged.values())
