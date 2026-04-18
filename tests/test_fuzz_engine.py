"""Tests for the async fuzzing engine.

Covers:
- XSS detection (reflected payload in response body)
- SQLi timing-based detection (slow response triggers timing matcher)
- False positive resistance (clean responses produce no findings)
- Injection-point discovery for query, form, JSON, header, cookie, path
- Confidence scoring logic
- Rate limiting behaviour
- Passive template execution (security-headers style)

Uses ``respx`` to mock HTTP responses so no real network traffic occurs.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import Endpoint, SeverityLevel
from sentinal_fuzz.fuzzer.engine import FuzzEngine, InjectionPoint, _get_part, _inject_json_field
from sentinal_fuzz.fuzzer.remediations import REMEDIATION_MAP
from sentinal_fuzz.fuzzer.template_schema import FuzzTemplate, Matcher
from sentinal_fuzz.utils.http import HttpClient, Response

# Passive detector template IDs that now fire automatically
_PASSIVE_IDS = frozenset({"header-checker", "exposure-checker"})


def _active_findings(findings: list) -> list:
    """Filter out passive-detector findings for active-scan tests."""
    return [f for f in findings if f.template_id not in _PASSIVE_IDS]

# ── Helpers ────────────────────────────────────────────────────────

def _make_config(**overrides: Any) -> ScanConfig:
    """Create a ScanConfig with sensible test defaults."""
    defaults = {
        "target": "http://testapp.local",
        "concurrency": 5,
        "rate_limit": 0,  # unlimited for speed
        "timeout": 5,
        "scan_profile": "quick",
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _make_response(
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
    elapsed_ms: float = 50.0,
) -> Response:
    """Create a mock Response without touching the network."""
    return Response(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
        elapsed_ms=elapsed_ms,
        url="http://testapp.local/page",
    )


def _xss_template() -> FuzzTemplate:
    """Minimal reflected XSS template."""
    return FuzzTemplate(
        id="xss-reflected",
        name="Reflected XSS",
        severity=SeverityLevel.HIGH,
        tags=["xss", "injection"],
        target_params=["query", "form"],
        payloads=["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>'],
        matchers=[
            Matcher(
                type="word",
                part="body",
                words=["<script>alert(1)</script>", "onerror=alert(1)"],
                condition="or",
            ),
        ],
        matchers_condition="or",
        stop_on_first_match=True,
        cwe="CWE-79",
        owasp="A03:2021-Injection",
    )


def _sqli_time_template() -> FuzzTemplate:
    """Minimal SQLi timing template."""
    return FuzzTemplate(
        id="sqli-time",
        name="SQL Injection — Time-Based Blind",
        severity=SeverityLevel.CRITICAL,
        tags=["sqli", "injection"],
        target_params=["query", "form", "cookie"],
        payloads=["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"],
        matchers=[
            Matcher(type="timing", part="response_time", threshold_ms=4500),
            Matcher(type="status", part="status", status=[200, 302, 500], condition="or"),
        ],
        matchers_condition="and",
        stop_on_first_match=True,
        cwe="CWE-89",
        owasp="A03:2021-Injection",
    )


def _passive_headers_template() -> FuzzTemplate:
    """Minimal passive security-headers template."""
    return FuzzTemplate(
        id="security-headers",
        name="Missing Security Headers",
        severity=SeverityLevel.LOW,
        target_params=[],
        payloads=[],
        matchers=[
            Matcher(
                type="header",
                part="header",
                negative=True,
                headers={"X-Frame-Options": "."},
            ),
        ],
        matchers_condition="or",
        stop_on_first_match=False,
        cwe="CWE-693",
    )


# ═══════════════════════════════════════════════════════════════════
# XSS Detection Tests
# ═══════════════════════════════════════════════════════════════════


class TestXSSDetection:
    """Test XSS reflected payload detection end-to-end."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_xss_detected_in_query_param(self):
        """Engine detects reflected XSS when the payload echoes back."""
        xss_payload = "<script>alert(1)</script>"

        def _echo_handler(request: httpx.Request) -> httpx.Response:
            """Echo back XSS payloads found in the query string."""
            q_value = str(request.url.params.get("q", ""))
            if xss_payload in q_value:
                return httpx.Response(
                    200,
                    text=f"<html><body>Results for {q_value}</body></html>",
                )
            return httpx.Response(
                200,
                text="<html><body>Search results</body></html>",
            )

        respx.get("http://testapp.local/search").mock(side_effect=_echo_handler)

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/search",
            method="GET",
            params={"q": "test"},
        )

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_xss_template()])

        findings = _active_findings(all_findings)
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.template_id == "xss-reflected"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.cwe == "CWE-79"
        assert "<script>alert(1)</script>" in finding.payload
        assert finding.confidence >= 0.5

    @respx.mock
    @pytest.mark.asyncio
    async def test_xss_not_detected_when_escaped(self):
        """Engine produces no finding when payload is HTML-escaped."""
        respx.get("http://testapp.local/search").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Search results</body></html>",
            ),
        )

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/search",
            method="GET",
            params={"q": "test"},
        )

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_xss_template()])

        assert len(_active_findings(all_findings)) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_xss_finding_has_remediation(self):
        """XSS finding includes remediation from REMEDIATION_MAP."""
        xss_payload = "<script>alert(1)</script>"

        def _echo_handler(request: httpx.Request) -> httpx.Response:
            """Echo back XSS payloads found in the query string."""
            q_value = str(request.url.params.get("q", ""))
            if xss_payload in q_value:
                return httpx.Response(
                    200,
                    text=f"<html><body>Results for {q_value}</body></html>",
                )
            return httpx.Response(
                200,
                text="<html><body>Search results</body></html>",
            )

        respx.get("http://testapp.local/search").mock(side_effect=_echo_handler)

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/search",
            method="GET",
            params={"q": "test"},
        )

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_xss_template()])

        findings = _active_findings(all_findings)
        assert len(findings) >= 1
        assert findings[0].remediation == REMEDIATION_MAP["xss-reflected"]


# ═══════════════════════════════════════════════════════════════════
# SQLi Timing Detection Tests
# ═══════════════════════════════════════════════════════════════════


class TestSQLiTimingDetection:
    """Test timing-based SQLi detection."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_sqli_detected_on_slow_response(self):
        """Engine detects SQLi when response is significantly delayed."""
        # Baseline: fast response
        baseline_called = False

        def baseline_handler(request: httpx.Request) -> httpx.Response:
            nonlocal baseline_called
            if not baseline_called:
                baseline_called = True
                return httpx.Response(200, text="Normal page")
            return httpx.Response(200, text="Normal page")

        respx.get("http://testapp.local/users").mock(side_effect=baseline_handler)

        config = _make_config()

        # We can't easily simulate elapsed time with respx, so test the
        # matcher logic directly instead.
        engine_instance = None
        async with HttpClient(timeout=5) as client:
            engine_instance = FuzzEngine(http_client=client, config=config)

        # Test matcher logic directly: slow response vs fast baseline
        baseline = _make_response(status_code=200, text="Normal", elapsed_ms=50)
        slow_response = _make_response(status_code=200, text="Normal", elapsed_ms=5500)

        template = _sqli_time_template()
        matched = engine_instance._evaluate_matchers(
            slow_response, baseline, template.matchers, template.matchers_condition,
        )
        assert len(matched) == 2  # timing + status both fired
        confidence = engine_instance._compute_confidence(matched)
        assert confidence == 0.9  # 2 matchers → high confidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_sqli_not_detected_on_fast_response(self):
        """Engine produces no finding when response is fast."""
        respx.get("http://testapp.local/users").mock(
            return_value=httpx.Response(200, text="Normal page"),
        )

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/users",
            method="GET",
            params={"id": "1"},
        )

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_sqli_time_template()])

        # Should have no active findings -- all responses are fast
        assert len(_active_findings(all_findings)) == 0

    def test_timing_only_match_low_confidence(self):
        """A timing-only match gets confidence = 0.5."""
        engine = FuzzEngine.__new__(FuzzEngine)
        timing_matcher = Matcher(type="timing", part="response_time", threshold_ms=4500)
        confidence = engine._compute_confidence([timing_matcher])
        assert confidence == 0.5


# ═══════════════════════════════════════════════════════════════════
# False Positive Resistance Tests
# ═══════════════════════════════════════════════════════════════════


class TestFalsePositiveResistance:
    """Ensure the engine does not produce findings on clean responses."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_clean_response_no_findings(self):
        """A perfectly safe response triggers no findings."""
        respx.get("http://testapp.local/page").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Welcome to our safe page</body></html>",
                headers={"content-type": "text/html"},
            ),
        )

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/page",
            method="GET",
            params={"q": "hello"},
        )

        templates = [_xss_template(), _sqli_time_template()]

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, templates)

        assert len(_active_findings(all_findings)) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_injectable_params_no_findings(self):
        """An endpoint with no injectable params produces no active findings."""
        respx.get("http://testapp.local/static").mock(
            return_value=httpx.Response(200, text="Static content"),
        )

        config = _make_config()
        endpoint = Endpoint(
            url="http://testapp.local/static",
            method="GET",
        )

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_xss_template()])

        assert len(_active_findings(all_findings)) == 0


# ═══════════════════════════════════════════════════════════════════
# Injection Point Discovery Tests
# ═══════════════════════════════════════════════════════════════════


class TestInjectionPointDiscovery:
    """Test _applicable_injection_points for all injection types."""

    def _make_engine(self) -> FuzzEngine:
        """Create an engine instance for testing (no HTTP needed)."""
        engine = FuzzEngine.__new__(FuzzEngine)
        return engine

    def test_query_params_discovered(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/search?q=test&page=1",
            method="GET",
            params={"sort": "asc"},
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["query"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        names = {p.name for p in points}
        assert "q" in names
        assert "page" in names
        assert "sort" in names
        assert all(p.kind == "query" for p in points)

    def test_form_fields_discovered(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/login",
            method="POST",
            forms=[
                {"name": "username", "value": "admin"},
                {"name": "password", "value": "secret"},
            ],
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["form"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        names = {p.name for p in points}
        assert "username" in names
        assert "password" in names
        assert all(p.kind == "form" for p in points)

    def test_json_fields_discovered(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/api/v1/users",
            method="POST",
            forms=[{"name": "email", "value": "test@example.com"}],
            params={"api_key": "abc123"},
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["json"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        names = {p.name for p in points}
        assert "email" in names
        assert "api_key" in names
        assert all(p.kind == "json" for p in points)

    def test_header_injection_points(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/page",
            method="GET",
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["header"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        names = {p.name for p in points}
        assert "User-Agent" in names
        assert "Referer" in names
        assert "X-Forwarded-For" in names
        assert all(p.kind == "header" for p in points)

    def test_cookie_injection_points(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/dashboard",
            method="GET",
            cookies={"session": "abc", "prefs": "dark"},
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["cookie"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        names = {p.name for p in points}
        assert "session" in names
        assert "prefs" in names
        assert all(p.kind == "cookie" for p in points)

    def test_path_segment_injection_points(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/users/42/profile",
            method="GET",
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["path"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        assert len(points) == 3  # users, 42, profile
        assert points[0].kind == "path"
        assert points[1].value == "42"

    def test_no_matching_params(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/page",
            method="GET",
        )
        template = FuzzTemplate(
            id="t", name="T", severity=SeverityLevel.INFO,
            target_params=["query", "form"],
        )
        points = engine._applicable_injection_points(endpoint, template)
        assert len(points) == 0


# ═══════════════════════════════════════════════════════════════════
# Matcher Tests
# ═══════════════════════════════════════════════════════════════════


class TestMatchers:
    """Test individual matcher implementations."""

    def test_word_matcher_case_insensitive(self):
        response = _make_response(text="<SCRIPT>ALERT(1)</SCRIPT>")
        matcher = Matcher(type="word", part="body", words=["<script>alert(1)</script>"])
        assert FuzzEngine._match_word(response, matcher) is True

    def test_word_matcher_no_match(self):
        response = _make_response(text="Safe content, no XSS here")
        matcher = Matcher(type="word", part="body", words=["<script>alert(1)</script>"])
        assert FuzzEngine._match_word(response, matcher) is False

    def test_word_matcher_and_condition(self):
        response = _make_response(text="has foo and bar in it")
        matcher = Matcher(type="word", part="body", words=["foo", "bar"], condition="and")
        assert FuzzEngine._match_word(response, matcher) is True

    def test_word_matcher_and_condition_partial(self):
        response = _make_response(text="has foo but not the other")
        matcher = Matcher(type="word", part="body", words=["foo", "bar"], condition="and")
        assert FuzzEngine._match_word(response, matcher) is False

    def test_regex_matcher_sql_error(self):
        response = _make_response(
            text="Error: SQL syntax error near MySQL query at line 1"
        )
        matcher = Matcher(
            type="regex", part="body",
            regex=[r"SQL syntax.*?MySQL"],
        )
        assert FuzzEngine._match_regex(response, matcher) is True

    def test_regex_matcher_no_match(self):
        response = _make_response(text="Everything is fine")
        matcher = Matcher(
            type="regex", part="body",
            regex=[r"SQL syntax.*?MySQL"],
        )
        assert FuzzEngine._match_regex(response, matcher) is False

    def test_status_matcher(self):
        response = _make_response(status_code=500)
        matcher = Matcher(type="status", part="status", status=[500, 503])
        assert FuzzEngine._match_status(response, matcher) is True

    def test_status_matcher_no_match(self):
        response = _make_response(status_code=200)
        matcher = Matcher(type="status", part="status", status=[500, 503])
        assert FuzzEngine._match_status(response, matcher) is False

    def test_timing_matcher_slow(self):
        baseline = _make_response(elapsed_ms=50)
        slow = _make_response(elapsed_ms=6000)
        matcher = Matcher(type="timing", part="response_time", threshold_ms=4500)
        assert FuzzEngine._match_timing(slow, baseline, matcher) is True

    def test_timing_matcher_fast(self):
        baseline = _make_response(elapsed_ms=50)
        fast = _make_response(elapsed_ms=100)
        matcher = Matcher(type="timing", part="response_time", threshold_ms=4500)
        assert FuzzEngine._match_timing(fast, baseline, matcher) is False

    def test_size_matcher_deviation(self):
        baseline = _make_response(text="x" * 1000)
        large = _make_response(text="y" * 2000)
        matcher = Matcher(type="size", part="body")
        assert FuzzEngine._match_size(large, baseline, matcher) is True

    def test_size_matcher_similar(self):
        baseline = _make_response(text="x" * 1000)
        similar = _make_response(text="x" * 1010)
        matcher = Matcher(type="size", part="body")
        assert FuzzEngine._match_size(similar, baseline, matcher) is False

    def test_header_matcher_found(self):
        response = _make_response(
            headers={"content-type": "text/html", "x-frame-options": "DENY"},
        )
        matcher = Matcher(
            type="header", part="header",
            headers={"x-frame-options": "DENY"},
        )
        assert FuzzEngine._match_header(response, matcher) is True

    def test_header_matcher_missing(self):
        response = _make_response(headers={"content-type": "text/html"})
        matcher = Matcher(
            type="header", part="header",
            headers={"x-frame-options": "."},
        )
        assert FuzzEngine._match_header(response, matcher) is False

    def test_negative_matcher_inverts(self):
        """negative=True inverts the result: absent header → match."""
        response = _make_response(headers={"content-type": "text/html"})
        matcher = Matcher(
            type="header", part="header",
            negative=True,
            headers={"X-Frame-Options": "."},
        )
        engine = FuzzEngine.__new__(FuzzEngine)
        assert engine._matches(response, response, matcher) is True


# ═══════════════════════════════════════════════════════════════════
# Confidence Scoring Tests
# ═══════════════════════════════════════════════════════════════════


class TestConfidenceScoring:
    """Test the confidence scoring logic."""

    def test_single_non_timing_matcher(self):
        engine = FuzzEngine.__new__(FuzzEngine)
        matcher = Matcher(type="word", part="body", words=["test"])
        assert engine._compute_confidence([matcher]) == 0.6

    def test_two_matchers(self):
        engine = FuzzEngine.__new__(FuzzEngine)
        m1 = Matcher(type="word", part="body", words=["test"])
        m2 = Matcher(type="status", part="status", status=[200])
        assert engine._compute_confidence([m1, m2]) == 0.9

    def test_timing_only(self):
        engine = FuzzEngine.__new__(FuzzEngine)
        m = Matcher(type="timing", part="response_time", threshold_ms=5000)
        assert engine._compute_confidence([m]) == 0.5

    def test_no_matchers(self):
        engine = FuzzEngine.__new__(FuzzEngine)
        assert engine._compute_confidence([]) == 0.0


# ═══════════════════════════════════════════════════════════════════
# Request Builder Tests
# ═══════════════════════════════════════════════════════════════════


class TestRequestBuilder:
    """Test _build_request for different injection point types."""

    def _make_engine(self) -> FuzzEngine:
        engine = FuzzEngine.__new__(FuzzEngine)
        return engine

    def test_query_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/search?q=test",
            method="GET",
            params={"sort": "asc"},
        )
        ip = InjectionPoint(kind="query", name="q", value="test")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert "q=PAYLOAD" in req.url
        assert "sort=asc" in req.url

    def test_form_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/login",
            method="POST",
            forms=[
                {"name": "user", "value": "admin"},
                {"name": "pass", "value": "secret"},
            ],
        )
        ip = InjectionPoint(kind="form", name="user", value="admin")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert req.method == "POST"
        assert req.content_type == "application/x-www-form-urlencoded"
        assert "user=PAYLOAD" in req.body
        assert "pass=secret" in req.body

    def test_json_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/api",
            method="POST",
            forms=[{"name": "email", "value": "old@test.com"}],
        )
        ip = InjectionPoint(kind="json", name="email", value="old@test.com")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert req.content_type == "application/json"
        import json
        body = json.loads(req.body)
        assert body["email"] == "PAYLOAD"

    def test_header_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(url="http://testapp.local/page", method="GET")
        ip = InjectionPoint(kind="header", name="User-Agent", value="")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert req.headers["User-Agent"] == "PAYLOAD"

    def test_cookie_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/page",
            method="GET",
            cookies={"session": "abc"},
        )
        ip = InjectionPoint(kind="cookie", name="session", value="abc")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert req.cookies["session"] == "PAYLOAD"

    def test_path_injection(self):
        engine = self._make_engine()
        endpoint = Endpoint(
            url="http://testapp.local/users/42/profile",
            method="GET",
        )
        ip = InjectionPoint(kind="path", name="1", value="42")
        req = engine._build_request(endpoint, ip, "PAYLOAD")
        assert "/users/PAYLOAD/profile" in req.url


# ═══════════════════════════════════════════════════════════════════
# Passive Template Tests
# ═══════════════════════════════════════════════════════════════════


class TestPassiveTemplates:
    """Test passive template execution (no payload injection)."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_missing_security_header_detected(self):
        """Passive template detects missing X-Frame-Options header."""
        respx.get("http://testapp.local/page").mock(
            return_value=httpx.Response(
                200,
                text="<html>Page</html>",
                headers={"content-type": "text/html"},
                # Note: no X-Frame-Options header
            ),
        )

        config = _make_config()
        endpoint = Endpoint(url="http://testapp.local/page", method="GET")

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_passive_headers_template()])

        # Should find header issues (from passive detectors OR template)
        assert len(all_findings) >= 1
        # At least one finding should relate to security headers
        assert any(
            f.template_id in ("security-headers", "header-checker")
            for f in all_findings
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_present_security_header_no_finding(self):
        """Passive template produces no finding when header is present."""
        respx.get("http://testapp.local/page").mock(
            return_value=httpx.Response(
                200,
                text="<html>Page</html>",
                headers={
                    "content-type": "text/html",
                    "x-frame-options": "DENY",
                },
            ),
        )

        config = _make_config()
        endpoint = Endpoint(url="http://testapp.local/page", method="GET")

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            all_findings = await engine.fuzz_endpoint(endpoint, [_passive_headers_template()])

        # The passive template matcher should NOT fire (header is present),
        # but passive detectors may still find other missing headers (CSP, XCTO).
        template_findings = [
            f for f in all_findings if f.template_id == "security-headers"
        ]
        assert len(template_findings) == 0


# ═══════════════════════════════════════════════════════════════════
# Remediation Map Tests
# ═══════════════════════════════════════════════════════════════════


class TestRemediationMap:
    """Test the REMEDIATION_MAP has entries for all known templates."""

    def test_all_template_ids_have_remediation(self):
        """Every built-in template should have a remediation entry."""
        expected_ids = {
            "xss-reflected", "sqli-error", "sqli-time",
            "path-traversal", "ssti-basic", "ssrf-basic",
            "open-redirect", "security-headers", "sensitive-exposure",
        }
        for tid in expected_ids:
            assert tid in REMEDIATION_MAP, f"Missing remediation for {tid}"
            assert len(REMEDIATION_MAP[tid]) > 20, (
                f"Remediation for {tid} is too short"
            )


# ═══════════════════════════════════════════════════════════════════
# Helper Function Tests
# ═══════════════════════════════════════════════════════════════════


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_get_part_body(self):
        resp = _make_response(text="body content")
        assert _get_part(resp, "body") == "body content"

    def test_get_part_status(self):
        resp = _make_response(status_code=404)
        assert _get_part(resp, "status") == "404"

    def test_get_part_header(self):
        resp = _make_response(headers={"x-test": "value"})
        result = _get_part(resp, "header")
        assert "x-test: value" in result

    def test_get_part_all(self):
        resp = _make_response(
            status_code=200, text="body",
            headers={"x-test": "val"},
        )
        result = _get_part(resp, "all")
        assert "200" in result
        assert "body" in result
        assert "x-test: val" in result

    def test_inject_json_field_top_level(self):
        obj = {"name": "old", "age": "30"}
        result = _inject_json_field(obj, "name", "PAYLOAD")
        assert result["name"] == "PAYLOAD"
        assert result["age"] == "30"

    def test_inject_json_field_nested(self):
        obj = {"user": {"name": "old", "email": "old@test.com"}}
        result = _inject_json_field(obj, "name", "PAYLOAD")
        assert result["user"]["name"] == "PAYLOAD"

    def test_inject_json_field_missing_key(self):
        obj = {"name": "value"}
        result = _inject_json_field(obj, "nonexistent", "PAYLOAD")
        assert result == {"name": "value"}
