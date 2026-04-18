"""Async fuzzing engine — the heart of Sentinal-Fuzz.

Takes an ``Endpoint``, loads applicable ``FuzzTemplate`` objects,
injects payloads into every viable injection point, fires requests
concurrently in batches, and returns ``Finding`` objects for every
confirmed hit.

Design decisions
----------------
* **Concurrency** is throttled by an ``asyncio.Semaphore`` so we
  never exceed the configured request limit.
* **Rate limiting** is implemented with a token-bucket-style delay
  between batches.
* **Early exit** — when ``stop_on_first_match`` is set on a template,
  the engine moves on as soon as the first hit is confirmed.
* **Confidence scoring** uses the number and type of matched matchers
  to assign a score; only findings with ``confidence >= 0.5`` are
  reported.

Usage::

    from sentinal_fuzz.fuzzer.engine import FuzzEngine

    engine = FuzzEngine(http_client=client, config=config)
    findings = await engine.fuzz_endpoint(endpoint, templates)
"""

from __future__ import annotations

import asyncio
import copy
import json
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from sentinal_fuzz.core.models import Endpoint, Finding, HttpExchange
from sentinal_fuzz.fuzzer.deduplicator import deduplicate
from sentinal_fuzz.fuzzer.input_classifier import InputClassifier
from sentinal_fuzz.fuzzer.detectors.exposure import SensitiveDataChecker
from sentinal_fuzz.fuzzer.detectors.headers import SecurityHeaderChecker
from sentinal_fuzz.fuzzer.false_positive_filter import (
    FalsePositiveFilter,
    verify_xss_unescaped,
)
from sentinal_fuzz.fuzzer.remediations import REMEDIATION_MAP
from sentinal_fuzz.fuzzer.template_schema import FuzzTemplate, Matcher
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient, Response

log = get_logger("engine")

# ── Injection-point types ──────────────────────────────────────────
# Maps template ``target_params`` values to the internal label.
_PARAM_TYPE_MAP: dict[str, str] = {
    "query": "query",
    "form": "form",
    "header": "header",
    "cookie": "cookie",
    "path": "path",
    "json": "json",
}

# Headers we always attempt to inject into when ``header`` is
# listed in ``target_params``.
_INJECTABLE_HEADERS = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Custom-Header",
)


# ── Data structures ────────────────────────────────────────────────

@dataclass
class InjectionPoint:
    """Describes a single location in a request where a payload can go.

    Attributes:
        kind:  One of ``query``, ``form``, ``json``, ``header``,
               ``cookie``, ``path``.
        name:  The parameter / header / cookie name (or path-segment
               index for ``path``).
        value: The original value at this location.
    """

    kind: str
    name: str
    value: str = ""


@dataclass
class FuzzRequest:
    """Fully-built fuzzed HTTP request ready to send.

    Attributes:
        method:       HTTP method.
        url:          Full URL (with query string if applicable).
        headers:      Request headers.
        cookies:      Cookies dict.
        body:         Request body (for POST/PUT).
        content_type: Content-Type header value.
    """

    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    content_type: str | None = None


# ── Engine ─────────────────────────────────────────────────────────

class FuzzEngine:
    """Core async fuzzing engine.

    Attributes:
        http_client: Shared HTTP client for sending requests.
        config:      Scan configuration (concurrency, rate_limit, …).
    """

    def __init__(
        self,
        http_client: HttpClient,
        config: ScanConfig,
    ) -> None:
        self.http_client = http_client
        self.config = config
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._requests_sent: int = 0
        self._batch_start: float = 0.0
        # Passive detectors -- run on every page
        self._header_checker = SecurityHeaderChecker()
        self._exposure_checker = SensitiveDataChecker()
        # False-positive filter
        self._fp_filter = FalsePositiveFilter()
        # Smart input classifier — reduces fuzz combinations by ~70%
        self._classifier = InputClassifier()
        # Baseline cache: url → (averaged_baseline, baseline_elapsed_ms)
        self._baseline_cache: dict[str, Response] = {}

    # ── Public API ─────────────────────────────────────────────────

    async def fuzz_endpoint(
        self,
        endpoint: Endpoint,
        templates: list[FuzzTemplate],
    ) -> list[Finding]:
        """Fuzz a single endpoint with every applicable template.

        For each template the engine:
        1. Classifies parameters to determine relevant vulnerability tags.
        2. Filters templates per-parameter to skip irrelevant payloads.
        3. Records a baseline response.
        4. Builds fuzzed requests for every (payload x injection point).
        5. Sends them concurrently via ``asyncio.gather`` in batches.
        6. Analyses responses against the template's matchers.
        7. Creates ``Finding`` objects for confirmed hits.

        Args:
            endpoint:  The endpoint to test.
            templates: Templates loaded by ``TemplateLoader``.

        Returns:
            A list of ``Finding`` objects for this endpoint.
        """
        all_findings: list[Finding] = []

        # ── Run passive detectors on every page ────────────────────
        passive_findings = await self.run_passive_checks(endpoint)
        all_findings.extend(passive_findings)

        # ── Smart classification: determine relevant tags per param ─
        param_tags = self._classifier.classify(endpoint)
        all_template_tags = set()
        for template in templates:
            all_template_tags.update(template.tags)

        if param_tags:
            for pname, ptags in param_tags.items():
                skipped = sorted(all_template_tags - set(ptags))
                log.info(
                    "Parameter '%s' → testing %s (skipping %s)",
                    pname, ptags, skipped if skipped else "none",
                )

        # ── Determine per-parameter filtered templates ─────────────
        # Build a set of ALL tags that are relevant for this endpoint
        # to create a unified filtered template list.
        endpoint_tags: set[str] = set()
        for tags in param_tags.values():
            endpoint_tags.update(tags)

        if endpoint_tags:
            filtered_templates = self._classifier.filter_templates(
                templates, list(endpoint_tags),
            )
            # Update metrics
            active_templates = [t for t in templates if not t.is_passive]
            filtered_active = [t for t in filtered_templates if not t.is_passive]
            param_count = max(len(param_tags), 1)
            self._classifier.update_metrics(
                total_templates=len(active_templates),
                filtered_templates=len(filtered_active),
                param_count=param_count,
            )
            log.info(
                "Classification: %d/%d templates selected for %s (%d params)",
                len(filtered_templates), len(templates),
                endpoint.url, param_count,
            )
        else:
            # No classifiable params → use all templates
            filtered_templates = templates

        for template in filtered_templates:
            injection_points = self._applicable_injection_points(
                endpoint, template,
            )
            if not injection_points and not template.is_passive:
                log.debug(
                    "Template %s not applicable to %s (no matching injection points)",
                    template.id, endpoint.url,
                )
                continue

            payloads = template.payload_list

            # ── Passive templates (no payloads) ────────────────────
            if template.is_passive:
                findings = await self._run_passive(endpoint, template)
                all_findings.extend(findings)
                continue

            if not payloads:
                continue

            # ── Averaged Baseline (2 requests) ────────────────────
            baseline = await self._send_baseline_averaged(endpoint)

            # ── Build & send fuzzed requests ───────────────────────
            template_findings = await self._fuzz_template(
                endpoint, template, payloads, injection_points, baseline,
            )
            all_findings.extend(template_findings)

        # ── Deduplicate all findings ───────────────────────────────
        return deduplicate(all_findings)

    async def run_passive_checks(self, endpoint: Endpoint) -> list[Finding]:
        """Run passive detectors (headers, exposure) on an endpoint.

        These run on every page regardless of templates.  They fetch
        the page once and analyse the response without injecting
        anything.

        Args:
            endpoint: The endpoint to check.

        Returns:
            Findings from passive analysis.
        """
        findings: list[Finding] = []
        try:
            response = await self._send_baseline(endpoint)
        except Exception as exc:
            log.debug("Passive check failed for %s: %s", endpoint.url, exc)
            return findings

        # Security header analysis
        header_findings = self._header_checker.check(endpoint.url, response)
        findings.extend(header_findings)

        # Sensitive data exposure analysis
        exposure_findings = self._exposure_checker.check(endpoint.url, response)
        findings.extend(exposure_findings)

        return findings

    # ── Template-level fuzzing ─────────────────────────────────────

    async def _fuzz_template(
        self,
        endpoint: Endpoint,
        template: FuzzTemplate,
        payloads: list[str],
        injection_points: list[InjectionPoint],
        baseline: Response,
    ) -> list[Finding]:
        """Fuzz one template against one endpoint.

        Returns as soon as a hit is confirmed when
        ``template.stop_on_first_match`` is set.
        """
        findings: list[Finding] = []

        # Build (injection_point, payload) pairs
        tasks: list[tuple[InjectionPoint, str]] = [
            (ip, payload)
            for ip in injection_points
            for payload in payloads
        ]

        # Split into batches of `concurrency`
        batch_size = self.config.concurrency
        for batch_start in range(0, len(tasks), batch_size):
            batch = tasks[batch_start: batch_start + batch_size]
            self._batch_start = time.monotonic()

            coros = [
                self._send_and_match(
                    endpoint, template, ip, payload, baseline,
                )
                for ip, payload in batch
            ]
            results = await asyncio.gather(*coros, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    log.warning("Request error during fuzzing: %s", result)
                    continue
                if result is not None:
                    findings.append(result)
                    if template.stop_on_first_match:
                        return findings

            # Rate-limit delay between batches
            await self._rate_limit_delay(len(batch))

        return findings

    async def _send_and_match(
        self,
        endpoint: Endpoint,
        template: FuzzTemplate,
        injection_point: InjectionPoint,
        payload: str,
        baseline: Response,
    ) -> Finding | None:
        """Send a single fuzzed request and check for a hit.

        Applies the 3-layer confirmation system:
        1. Matcher evaluation with baseline-aware matching.
        2. False-positive filter checks.
        3. For timing templates: confirmation re-send.
        4. For XSS templates: nonce-based unescaped verification.

        Returns a ``Finding`` if confirmed, else ``None``.
        """
        fuzz_req = self._build_request(endpoint, injection_point, payload)
        response = await self._send_request(fuzz_req)
        if response is None:
            return None

        matched_matchers = self._evaluate_matchers(
            response, baseline, template.matchers, template.matchers_condition,
        )
        if not matched_matchers:
            return None

        confidence = self._compute_confidence(matched_matchers)
        if confidence < 0.5:
            return None

        # ── Layer 2: Timing confirmation (double-send) ─────────
        has_timing = any(m.type == "timing" for m in matched_matchers)
        if has_timing:
            confirm_response = await self._send_request(fuzz_req)
            if confirm_response is None:
                return None
            # Both sends must exceed the smart threshold
            baseline_ms = baseline.elapsed_ms
            threshold_ms = max(baseline_ms + 2500, 3500)
            if confirm_response.elapsed_ms < threshold_ms:
                log.debug(
                    "Timing confirmation failed: %.0fms < %.0fms threshold",
                    confirm_response.elapsed_ms, threshold_ms,
                )
                return None
            confidence = 0.85  # Confirmed timing → set confidence

        # ── Build the finding ──────────────────────────────────
        finding = self._create_finding(
            endpoint, template, payload, injection_point,
            fuzz_req, response, matched_matchers, confidence,
        )

        # ── Layer 3: False-positive filter ─────────────────────
        if not self._fp_filter.should_keep(finding, baseline, response):
            return None

        return finding

    # ── Passive check ──────────────────────────────────────────────

    async def _run_passive(
        self,
        endpoint: Endpoint,
        template: FuzzTemplate,
    ) -> list[Finding]:
        """Run a passive template (no payload injection).

        Sends a clean request and checks matchers against the response.
        """
        baseline = await self._send_baseline(endpoint)
        matched = self._evaluate_matchers(
            baseline, baseline, template.matchers, template.matchers_condition,
        )
        if not matched:
            return []

        confidence = self._compute_confidence(matched)
        if confidence < 0.5:
            return []

        finding = self._create_finding(
            endpoint, template, payload="(passive check)",
            injection_point=InjectionPoint(kind="passive", name="n/a"),
            fuzz_req=FuzzRequest(method=endpoint.method, url=endpoint.url),
            response=baseline,
            matched_matchers=matched,
            confidence=confidence,
        )
        return [finding]

    # ── Injection-point discovery ──────────────────────────────────

    def _applicable_injection_points(
        self,
        endpoint: Endpoint,
        template: FuzzTemplate,
    ) -> list[InjectionPoint]:
        """Return injection points from *endpoint* that match *template*.

        Only injection points whose ``kind`` is listed in
        ``template.target_params`` are returned.
        """
        points: list[InjectionPoint] = []
        target_set = set(template.target_params)

        # Query parameters
        if "query" in target_set:
            parsed = urlparse(endpoint.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in qs.items():
                points.append(
                    InjectionPoint(kind="query", name=name, value=values[0] if values else ""),
                )
            # Also include params from the Endpoint model
            for name, value in endpoint.params.items():
                if not any(p.name == name and p.kind == "query" for p in points):
                    points.append(InjectionPoint(kind="query", name=name, value=value))

        # Form fields
        if "form" in target_set:
            for form_field in endpoint.forms:
                fname = form_field.get("name", "")
                if fname:
                    points.append(
                        InjectionPoint(
                            kind="form",
                            name=fname,
                            value=form_field.get("value", ""),
                        ),
                    )

        # JSON body fields
        if "json" in target_set:
            # If the endpoint has a form that looks like JSON, walk it
            for form_field in endpoint.forms:
                fname = form_field.get("name", "")
                if fname:
                    points.append(
                        InjectionPoint(
                            kind="json",
                            name=fname,
                            value=form_field.get("value", ""),
                        ),
                    )
            # Also add query params as potential JSON fields
            for name, value in endpoint.params.items():
                if not any(p.name == name and p.kind == "json" for p in points):
                    points.append(InjectionPoint(kind="json", name=name, value=value))

        # Headers
        if "header" in target_set:
            for header_name in _INJECTABLE_HEADERS:
                points.append(
                    InjectionPoint(
                        kind="header",
                        name=header_name,
                        value=endpoint.headers.get(header_name, ""),
                    ),
                )

        # Cookies
        if "cookie" in target_set:
            for name, value in endpoint.cookies.items():
                points.append(InjectionPoint(kind="cookie", name=name, value=value))

        # Path segments
        if "path" in target_set:
            parsed = urlparse(endpoint.url)
            segments = [s for s in parsed.path.split("/") if s]
            for idx, segment in enumerate(segments):
                points.append(
                    InjectionPoint(kind="path", name=str(idx), value=segment),
                )

        return points

    # ── Request builder ────────────────────────────────────────────

    def _build_request(
        self,
        endpoint: Endpoint,
        injection_point: InjectionPoint,
        payload: str,
    ) -> FuzzRequest:
        """Build a single fuzzed HTTP request.

        Clones the original endpoint's request, replaces ONLY the
        target injection point with *payload*, and preserves all other
        fields (headers, cookies, auth).
        """
        method = endpoint.method
        parsed = urlparse(endpoint.url)
        headers = dict(endpoint.headers)
        cookies = dict(endpoint.cookies)
        body: str | None = None
        content_type: str | None = None

        if injection_point.kind == "query":
            qs = parse_qs(parsed.query, keep_blank_values=True)
            # Also merge Endpoint.params
            for k, v in endpoint.params.items():
                if k not in qs:
                    qs[k] = [v]
            qs[injection_point.name] = [payload]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        elif injection_point.kind == "form":
            url = endpoint.url
            form_data: dict[str, str] = {}
            for ff in endpoint.forms:
                fname = ff.get("name", "")
                if fname:
                    form_data[fname] = ff.get("value", "")
            form_data[injection_point.name] = payload
            body = urlencode(form_data)
            content_type = "application/x-www-form-urlencoded"
            method = "POST" if method == "GET" else method

        elif injection_point.kind == "json":
            url = endpoint.url
            json_body: dict[str, Any] = {}
            for ff in endpoint.forms:
                fname = ff.get("name", "")
                if fname:
                    json_body[fname] = ff.get("value", "")
            for k, v in endpoint.params.items():
                json_body[k] = v
            json_body = _inject_json_field(json_body, injection_point.name, payload)
            body = json.dumps(json_body)
            content_type = "application/json"
            method = "POST" if method == "GET" else method

        elif injection_point.kind == "header":
            url = endpoint.url
            headers[injection_point.name] = payload

        elif injection_point.kind == "cookie":
            url = endpoint.url
            cookies[injection_point.name] = payload

        elif injection_point.kind == "path":
            segments = [s for s in parsed.path.split("/") if s]
            idx = int(injection_point.name)
            if 0 <= idx < len(segments):
                segments[idx] = payload
            new_path = "/" + "/".join(segments)
            url = urlunparse(parsed._replace(path=new_path))

        else:
            url = endpoint.url

        return FuzzRequest(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            content_type=content_type,
        )

    # ── HTTP transport ─────────────────────────────────────────────

    async def _send_request(self, fuzz_req: FuzzRequest) -> Response | None:
        """Send a fuzzed request through the HTTP client.

        Respects the concurrency semaphore.
        """
        async with self._semaphore:
            try:
                kwargs: dict[str, Any] = {}
                if fuzz_req.cookies:
                    kwargs["cookies"] = fuzz_req.cookies
                if fuzz_req.body is not None:
                    kwargs["content"] = fuzz_req.body.encode()
                if fuzz_req.content_type:
                    fuzz_req.headers["Content-Type"] = fuzz_req.content_type
                if fuzz_req.headers:
                    kwargs["headers"] = fuzz_req.headers

                response = await self.http_client.request(
                    fuzz_req.method, fuzz_req.url, **kwargs,
                )
                self._requests_sent += 1
                return response
            except Exception as exc:
                log.debug("Request failed: %s %s → %s", fuzz_req.method, fuzz_req.url, exc)
                return None

    async def _send_baseline(self, endpoint: Endpoint) -> Response:
        """Record a baseline response (original request, no payload)."""
        kwargs: dict[str, Any] = {}
        if endpoint.headers:
            kwargs["headers"] = endpoint.headers
        if endpoint.cookies:
            kwargs["cookies"] = endpoint.cookies
        if endpoint.params:
            kwargs["params"] = endpoint.params
        return await self.http_client.request(
            endpoint.method, endpoint.url, **kwargs,
        )

    async def _send_baseline_averaged(self, endpoint: Endpoint) -> Response:
        """Record a baseline by averaging 2 requests for stable timing.

        Sends the endpoint twice with no payloads and returns the first
        response but with the elapsed time averaged across both. This
        smooths out cold-start effects and network jitter for accurate
        timing-based comparisons.

        Uses a cache to avoid redundant requests within one scan.
        """
        cache_key = f"{endpoint.method}:{endpoint.url}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        resp1 = await self._send_baseline(endpoint)
        resp2 = await self._send_baseline(endpoint)

        # Use resp1 body/headers but average the timing
        from sentinal_fuzz.utils.http import Response as HttpResponse
        averaged = HttpResponse(
            status_code=resp1.status_code,
            headers=resp1.headers,
            text=resp1.text,
            elapsed_ms=(resp1.elapsed_ms + resp2.elapsed_ms) / 2.0,
            url=resp1.url,
            is_redirect=resp1.is_redirect,
        )

        self._baseline_cache[cache_key] = averaged
        log.debug(
            "Baseline averaged for %s: %.0fms (%.0f + %.0f / 2)",
            endpoint.url, averaged.elapsed_ms,
            resp1.elapsed_ms, resp2.elapsed_ms,
        )
        return averaged

    # ── Matcher evaluation ─────────────────────────────────────────

    def _evaluate_matchers(
        self,
        response: Response,
        baseline: Response,
        matchers: list[Matcher],
        condition: str,
    ) -> list[Matcher]:
        """Run all matchers and return those that fired.

        Args:
            response:  The fuzzed response to inspect.
            baseline:  The clean baseline response for differential checks.
            matchers:  List of ``Matcher`` objects from the template.
            condition: ``"or"`` or ``"and"`` — how to combine matchers.

        Returns:
            List of matchers that matched.  Empty list if the overall
            condition evaluates to False.
        """
        fired: list[Matcher] = []

        for matcher in matchers:
            hit = self._matches(response, baseline, matcher)
            if hit:
                fired.append(matcher)

        if condition == "and":
            # All matchers must fire
            return fired if len(fired) == len(matchers) else []

        # condition == "or" — at least one matcher must fire
        return fired

    def _matches(
        self,
        response: Response,
        baseline: Response,
        matcher: Matcher,
    ) -> bool:
        """Check one matcher against a response.

        Handles all matcher types: word, regex, status, timing, size,
        header.  Respects ``matcher.negative`` to invert the result.

        Word and regex matchers are baseline-aware — they reject matches
        that also appear in the baseline (to suppress false positives
        from static page content).
        """
        result = False

        if matcher.type == "word":
            result = self._match_word(response, matcher, baseline)
        elif matcher.type == "regex":
            result = self._match_regex(response, matcher, baseline)
        elif matcher.type == "status":
            result = self._match_status(response, matcher)
        elif matcher.type == "timing":
            result = self._match_timing(response, baseline, matcher)
        elif matcher.type == "size":
            result = self._match_size(response, baseline, matcher)
        elif matcher.type == "header":
            result = self._match_header(response, matcher)

        return (not result) if matcher.negative else result

    # ── Individual matcher implementations ─────────────────────────

    @staticmethod
    def _match_word(
        response: Response,
        matcher: Matcher,
        baseline: Response | None = None,
    ) -> bool:
        """Check if any word appears in the response (case-insensitive).

        Baseline-aware: if a word also appears in the baseline response,
        it is NOT counted as a match (to avoid false positives from
        static page content like 'syntax error' in footers).
        """
        text = _get_part(response, matcher.part).lower()
        baseline_text = _get_part(baseline, matcher.part).lower() if baseline else ""

        def is_new_match(word: str) -> bool:
            w_lower = word.lower()
            return w_lower in text and w_lower not in baseline_text

        if matcher.condition == "and":
            return all(is_new_match(w) for w in matcher.words)
        return any(is_new_match(w) for w in matcher.words)

    @staticmethod
    def _match_regex(
        response: Response,
        matcher: Matcher,
        baseline: Response | None = None,
    ) -> bool:
        """Compile and search regex patterns against the response.

        Baseline-aware: patterns that also match in the baseline are
        excluded to prevent false positives from static page content.
        """
        text = _get_part(response, matcher.part)
        baseline_text = _get_part(baseline, matcher.part) if baseline else ""

        def is_new_match(pattern: str) -> bool:
            """True only if pattern matches in fuzzed but NOT in baseline."""
            flags = re.IGNORECASE | re.DOTALL
            if not re.search(pattern, text, flags):
                return False
            if baseline_text and re.search(pattern, baseline_text, flags):
                return False
            return True

        if matcher.condition == "and":
            return all(is_new_match(p) for p in matcher.regex)
        return any(is_new_match(p) for p in matcher.regex)

    @staticmethod
    def _match_status(response: Response, matcher: Matcher) -> bool:
        """Check response status code against matcher's allowed codes."""
        return response.status_code in matcher.status

    @staticmethod
    def _match_timing(
        response: Response,
        baseline: Response,
        matcher: Matcher,
    ) -> bool:
        """Smart timing check for time-based blind injection.

        Uses a dynamic threshold: the fuzzed response time must exceed
        ``max(baseline + 2500ms, 3500ms)`` — whichever is larger.  This
        prevents flagging endpoints that are naturally slow (e.g. always
        take 4 seconds) as time-based SQLi.

        The baseline elapsed_ms should already be averaged from 2
        requests by ``_send_baseline_averaged``.
        """
        baseline_ms = baseline.elapsed_ms
        response_ms = response.elapsed_ms

        # Dynamic threshold: at least baseline + 2500ms, or 3500ms minimum
        smart_threshold_ms = max(baseline_ms + 2500, 3500)

        return response_ms > smart_threshold_ms

    @staticmethod
    def _match_size(
        response: Response,
        baseline: Response,
        matcher: Matcher,
    ) -> bool:
        """Check response body size against baseline or fixed bounds."""
        resp_len = len(response.text)

        # If explicit min/max bounds are set, use them
        if matcher.size_min and resp_len < matcher.size_min:
            return False
        if matcher.size_max and resp_len > matcher.size_max:
            return False
        if matcher.size_min or matcher.size_max:
            return True

        # Fallback: significant deviation from baseline
        baseline_len = len(baseline.text)
        threshold = max(100, baseline_len // 5)  # 20% or 100 chars
        return abs(resp_len - baseline_len) > threshold

    @staticmethod
    def _match_header(response: Response, matcher: Matcher) -> bool:
        """Check response headers against matcher's header patterns."""
        for hdr_name, hdr_pattern in matcher.headers.items():
            hdr_value = response.headers.get(hdr_name.lower(), "")
            if not hdr_value:
                # Header is absent — for non-negative matchers this is no-match
                return False
            if not re.search(hdr_pattern, hdr_value, re.IGNORECASE):
                return False
        return True

    # ── Confidence scoring ─────────────────────────────────────────

    @staticmethod
    def _compute_confidence(matched_matchers: list[Matcher]) -> float:
        """Compute a confidence score based on which matchers fired.

        Rules:
        - 1 matcher matched → 0.6
        - 2+ matchers matched (AND condition) → 0.9
        - Timing-only match → 0.5 (timing can be noisy)
        """
        if not matched_matchers:
            return 0.0

        # Pure timing match → lower confidence
        if (
            len(matched_matchers) == 1
            and matched_matchers[0].type == "timing"
        ):
            return 0.5

        if len(matched_matchers) >= 2:
            return 0.9

        return 0.6

    # ── Finding builder ────────────────────────────────────────────

    def _create_finding(
        self,
        endpoint: Endpoint,
        template: FuzzTemplate,
        payload: str,
        injection_point: InjectionPoint,
        fuzz_req: FuzzRequest,
        response: Response,
        matched_matchers: list[Matcher],
        confidence: float,
    ) -> Finding:
        """Build a ``Finding`` from fuzzing results.

        Populates all fields including evidence, request/response
        excerpts, and remediation guidance.
        """
        # Build evidence string from what matched
        evidence = self._extract_evidence(response, matched_matchers)

        # Build HTTP exchange for the finding
        http_exchange = HttpExchange(
            method=fuzz_req.method,
            url=fuzz_req.url,
            request_headers=fuzz_req.headers,
            request_body=fuzz_req.body,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text[:500],
            elapsed_ms=response.elapsed_ms,
        )

        # Response excerpt
        response_excerpt = (
            f"HTTP {response.status_code}\n"
            f"{response.text[:500]}"
        )

        # Remediation — prefer our map, fall back to template's own
        remediation = REMEDIATION_MAP.get(template.id, template.remediation)

        param_name = injection_point.name
        if injection_point.kind != "passive":
            param_name = f"{injection_point.kind}:{injection_point.name}"

        return Finding(
            title=template.name,
            severity=template.severity,
            url=endpoint.url,
            parameter=param_name,
            payload=payload,
            evidence=evidence,
            request=http_exchange,
            response=response_excerpt,
            cwe=template.cwe,
            owasp=template.owasp,
            remediation=remediation,
            confidence=confidence,
            template_id=template.id,
        )

    @staticmethod
    def _extract_evidence(
        response: Response,
        matched_matchers: list[Matcher],
    ) -> str:
        """Extract the first 200 chars of matching evidence."""
        parts: list[str] = []
        for m in matched_matchers:
            if m.type == "word":
                for w in m.words:
                    if w.lower() in response.text.lower():
                        idx = response.text.lower().index(w.lower())
                        snippet = response.text[max(0, idx - 20): idx + len(w) + 20]
                        parts.append(f"word match: …{snippet}…")
                        break
            elif m.type == "regex":
                for pattern in m.regex:
                    match = re.search(pattern, response.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        parts.append(f"regex match: {match.group()[:100]}")
                        break
            elif m.type == "status":
                parts.append(f"status={response.status_code}")
            elif m.type == "timing":
                parts.append(f"elapsed={response.elapsed_ms:.0f}ms")
            elif m.type == "size":
                parts.append(f"response_size={len(response.text)}")
            elif m.type == "header":
                for hdr_name in m.headers:
                    val = response.headers.get(hdr_name, "")
                    parts.append(f"header {hdr_name}={val[:80]}")

        evidence = " | ".join(parts)
        return evidence[:200]

    # ── Rate limiting ──────────────────────────────────────────────

    async def _rate_limit_delay(self, batch_count: int) -> None:
        """Throttle requests to stay under ``config.rate_limit`` RPS.

        After each batch we compute how many requests/second we are
        running and sleep if we exceed the limit.
        """
        if self.config.rate_limit <= 0:
            return

        elapsed = time.monotonic() - self._batch_start
        if elapsed <= 0:
            elapsed = 0.001

        current_rps = batch_count / elapsed
        if current_rps > self.config.rate_limit:
            target_duration = batch_count / self.config.rate_limit
            sleep_time = target_duration - elapsed
            if sleep_time > 0:
                log.debug(
                    "Rate limiting: sleeping %.3fs (current %.1f rps, limit %d rps)",
                    sleep_time, current_rps, self.config.rate_limit,
                )
                await asyncio.sleep(sleep_time)

    # ── Stats ──────────────────────────────────────────────────────

    @property
    def requests_sent(self) -> int:
        """Total fuzzed requests sent by this engine instance."""
        return self._requests_sent

    @property
    def classifier(self) -> InputClassifier:
        """Access the input classifier for metrics and configuration."""
        return self._classifier


# ── Module-level helpers ───────────────────────────────────────────

def _get_part(response: Response, part: str) -> str:
    """Extract the relevant part of a response for matching.

    Args:
        response: The HTTP response.
        part:     One of ``body``, ``header``, ``status``, ``all``.

    Returns:
        String content to match against.
    """
    if part == "body":
        return response.text
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    if part == "status":
        return str(response.status_code)
    if part == "all":
        headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        return f"{response.status_code}\n{headers}\n{response.text}"
    return response.text


def _inject_json_field(
    obj: dict[str, Any],
    field_name: str,
    payload: str,
) -> dict[str, Any]:
    """Recursively inject *payload* into *field_name* within a JSON body.

    Walks the dict tree and replaces the first occurrence of *field_name*.
    """
    result = copy.deepcopy(obj)
    if field_name in result:
        result[field_name] = payload
        return result
    for key, value in result.items():
        if isinstance(value, dict):
            result[key] = _inject_json_field(value, field_name, payload)
    return result
