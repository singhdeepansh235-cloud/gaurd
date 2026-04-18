"""Tests for vulnerability detectors.

Covers:
- SSRFDetector: canary generation, response analysis, param detection
- SSTIDetector: probe matching, engine error detection, baseline isolation
- PathTraversalDetector: payload generation, Linux/Windows signature matching
- SecurityHeaderChecker: all header checks (CSP, XFO, XCTO, HSTS, cookies)
- SensitiveDataChecker: AWS keys, private keys, JWT, stack traces, DB strings
- Engine passive integration: passive checks run on every page
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import Endpoint, SeverityLevel
from sentinal_fuzz.fuzzer.detectors.exposure import SensitiveDataChecker
from sentinal_fuzz.fuzzer.detectors.headers import SecurityHeaderChecker
from sentinal_fuzz.fuzzer.detectors.path_traversal import PathTraversalDetector
from sentinal_fuzz.fuzzer.detectors.ssrf import SSRFDetector
from sentinal_fuzz.fuzzer.detectors.ssti import SSTIDetector
from sentinal_fuzz.fuzzer.engine import FuzzEngine
from sentinal_fuzz.utils.http import HttpClient, Response

# ── Helpers ────────────────────────────────────────────────────────

def _make_response(
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
    elapsed_ms: float = 50.0,
) -> Response:
    """Create a mock Response."""
    return Response(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
        elapsed_ms=elapsed_ms,
        url="http://testapp.local/page",
    )


def _make_config(**overrides: Any) -> ScanConfig:
    """ScanConfig with test defaults."""
    defaults = {
        "target": "http://testapp.local",
        "concurrency": 5,
        "rate_limit": 0,
        "timeout": 5,
        "scan_profile": "quick",
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


# ═══════════════════════════════════════════════════════════════════
# SSRF Detector Tests
# ═══════════════════════════════════════════════════════════════════


class TestSSRFDetector:
    """Test SSRF detection logic."""

    def test_canary_domain_unique(self):
        """Each SSRFDetector instance gets a unique canary domain."""
        d1 = SSRFDetector()
        d2 = SSRFDetector()
        assert d1.canary_domain != d2.canary_domain

    def test_canary_url_format(self):
        """Canary URL follows the expected format."""
        d = SSRFDetector()
        assert d.canary_url.startswith("http://ssrf-")
        assert ".sentinal.local/callback" in d.canary_url

    def test_generate_payloads(self):
        """Payloads include the canary and internal targets."""
        d = SSRFDetector()
        payloads = d.generate_payloads()
        assert any(d.canary_domain in p for p in payloads)
        assert any("127.0.0.1" in p for p in payloads)
        assert any("169.254.169.254" in p for p in payloads)
        assert len(payloads) >= 5

    def test_is_ssrf_param_true(self):
        """Known SSRF parameter names are recognized."""
        assert SSRFDetector.is_ssrf_param("url") is True
        assert SSRFDetector.is_ssrf_param("redirect_url") is True
        assert SSRFDetector.is_ssrf_param("callback") is True
        assert SSRFDetector.is_ssrf_param("URL") is True  # case-insensitive

    def test_is_ssrf_param_false(self):
        """Normal parameter names are not flagged."""
        assert SSRFDetector.is_ssrf_param("username") is False
        assert SSRFDetector.is_ssrf_param("email") is False

    def test_detect_internal_ip(self):
        """Internal IPs in response body are flagged."""
        d = SSRFDetector()
        resp = _make_response(text="Server at 192.168.1.100:8080")
        evidence = d.analyze_response(resp)
        assert any("192.168" in e for e in evidence)

    def test_detect_aws_metadata(self):
        """AWS metadata keywords are detected."""
        d = SSRFDetector()
        resp = _make_response(text='{"ami-id": "ami-12345", "instance-id": "i-abc"}')
        evidence = d.analyze_response(resp)
        assert any("ami-id" in e for e in evidence)
        assert any("instance-id" in e for e in evidence)

    def test_detect_canary_in_response(self):
        """Canary domain in response proves DNS resolution."""
        d = SSRFDetector()
        resp = _make_response(text=f"Fetched content from {d.canary_domain}")
        evidence = d.analyze_response(resp)
        assert any("Canary" in e for e in evidence)

    def test_clean_response_no_evidence(self):
        """Clean response produces no SSRF evidence."""
        d = SSRFDetector()
        resp = _make_response(text="<html><body>Hello world</body></html>")
        evidence = d.analyze_response(resp)
        assert len(evidence) == 0

    def test_create_finding(self):
        """create_finding produces a valid Finding."""
        d = SSRFDetector()
        finding = d.create_finding(
            url="http://victim.com/api",
            parameter="url",
            payload="http://127.0.0.1",
            evidence=["Internal IP found: 127.0.0.1"],
        )
        assert finding.severity == SeverityLevel.HIGH
        assert finding.cwe == "CWE-918"
        assert finding.template_id == "ssrf-detector"


# ═══════════════════════════════════════════════════════════════════
# SSTI Detector Tests
# ═══════════════════════════════════════════════════════════════════


class TestSSTIDetector:
    """Test SSTI detection logic."""

    def test_get_probes(self):
        """Probes include all major template engines."""
        probes = SSTIDetector.get_probes()
        assert len(probes) >= 5
        engines = {p.engine for p in probes}
        assert any("Jinja2" in e for e in engines)
        assert any("Freemarker" in e for e in engines)
        assert any("ERB" in e for e in engines)

    def test_get_payloads(self):
        """get_payloads returns a flat list of strings."""
        payloads = SSTIDetector.get_payloads()
        assert "{{7*7}}" in payloads
        assert "${7*7}" in payloads

    def test_probe_match_jinja2(self):
        """Jinja2 probe matches when 49 appears in response."""
        from sentinal_fuzz.fuzzer.detectors.ssti import SSTIProbe

        probe = SSTIProbe(payload="{{7*7}}", expected="49", engine="Jinja2")
        # 49 appears in fuzzed response but not baseline
        assert SSTIDetector.check_probe(probe, "Result: 49", "Some page") is True

    def test_probe_no_match_baseline_has_49(self):
        """Probe does NOT match if baseline already has '49'."""
        from sentinal_fuzz.fuzzer.detectors.ssti import SSTIProbe

        probe = SSTIProbe(payload="{{7*7}}", expected="49", engine="Jinja2")
        # Both have same count of "49"
        assert SSTIDetector.check_probe(probe, "Page 49", "Page 49") is False

    def test_probe_jinja2_string_repeat(self):
        """Jinja2 string repeat probe 7*'7' -> 7777777."""
        from sentinal_fuzz.fuzzer.detectors.ssti import SSTIProbe

        probe = SSTIProbe(payload="{{7*'7'}}", expected="7777777", engine="Jinja2")
        assert SSTIDetector.check_probe(probe, "7777777", "") is True

    def test_detect_engine_errors_jinja2(self):
        """Jinja2 error messages are detected."""
        errors = SSTIDetector.detect_engine_errors(
            "jinja2.exceptions.UndefinedError: 'foo' is undefined",
        )
        assert len(errors) >= 1
        assert any("Jinja2" in engine for _, engine in errors)

    def test_detect_engine_errors_none(self):
        """Clean response has no engine errors."""
        errors = SSTIDetector.detect_engine_errors("Hello world")
        assert len(errors) == 0

    def test_create_finding(self):
        """create_finding produces a valid Finding."""
        finding = SSTIDetector.create_finding(
            url="http://victim.com/template",
            parameter="name",
            payload="{{7*7}}",
            engine="Jinja2",
            evidence="49 found in response",
        )
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.cwe == "CWE-94"
        assert "Jinja2" in finding.title


# ═══════════════════════════════════════════════════════════════════
# Path Traversal Detector Tests
# ═══════════════════════════════════════════════════════════════════


class TestPathTraversalDetector:
    """Test path traversal detection logic."""

    def test_get_payloads_not_empty(self):
        """Payloads list is populated."""
        payloads = PathTraversalDetector.get_payloads()
        assert len(payloads) > 10

    def test_payloads_include_encoded_variants(self):
        """URL-encoded and double-encoded variants are present."""
        payloads = PathTraversalDetector.get_payloads()
        assert any("%2e%2e%2f" in p for p in payloads)
        assert any("%252e%252e%252f" in p for p in payloads)

    def test_payloads_include_null_byte(self):
        """Null-byte bypass payloads are included."""
        payloads = PathTraversalDetector.get_payloads()
        assert any("%00" in p for p in payloads)

    def test_detect_etc_passwd(self):
        """Linux /etc/passwd content is detected."""
        text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
        evidence = PathTraversalDetector.analyze_response(text)
        assert len(evidence) >= 1
        assert any("/etc/passwd" in e for e in evidence)

    def test_detect_win_ini(self):
        """Windows win.ini content is detected."""
        text = "; for 16-bit app support\n[fonts]\n[extensions]"
        evidence = PathTraversalDetector.analyze_response(text)
        assert len(evidence) >= 1
        assert any("win.ini" in e for e in evidence)

    def test_detect_boot_ini(self):
        """Windows boot.ini content is detected."""
        text = "[boot loader]\ntimeout=30\n[operating systems]"
        evidence = PathTraversalDetector.analyze_response(text)
        assert len(evidence) >= 1
        assert any("boot.ini" in e for e in evidence)

    def test_clean_response_no_evidence(self):
        """Normal HTML page produces no evidence."""
        text = "<html><body>Welcome to our site</body></html>"
        evidence = PathTraversalDetector.analyze_response(text)
        assert len(evidence) == 0

    def test_create_finding(self):
        """create_finding produces a valid Finding."""
        finding = PathTraversalDetector.create_finding(
            url="http://victim.com/read",
            parameter="file",
            payload="../../../../etc/passwd",
            evidence=["Linux file (/etc/passwd): root:x:0:0:"],
        )
        assert finding.severity == SeverityLevel.HIGH
        assert finding.cwe == "CWE-22"


# ═══════════════════════════════════════════════════════════════════
# Security Header Checker Tests
# ═══════════════════════════════════════════════════════════════════


class TestSecurityHeaderChecker:
    """Test passive security header analysis."""

    def _checker(self) -> SecurityHeaderChecker:
        return SecurityHeaderChecker()

    def test_missing_csp(self):
        """Missing CSP header produces a finding."""
        resp = _make_response(headers={"content-type": "text/html"})
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)

    def test_missing_xfo(self):
        """Missing X-Frame-Options produces a finding."""
        resp = _make_response(headers={"content-type": "text/html"})
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert any("X-Frame-Options" in t for t in titles)

    def test_xfo_present_no_finding(self):
        """Present X-Frame-Options suppresses the finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "X-Frame-Options": "DENY",
        })
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert not any("X-Frame-Options" in t for t in titles)

    def test_csp_frame_ancestors_suppresses_xfo(self):
        """CSP frame-ancestors suppresses X-Frame-Options finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "Content-Security-Policy": "frame-ancestors 'self'",
        })
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert not any("X-Frame-Options" in t for t in titles)

    def test_missing_xcto(self):
        """Missing X-Content-Type-Options: nosniff."""
        resp = _make_response(headers={"content-type": "text/html"})
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert any("X-Content-Type-Options" in t for t in titles)

    def test_xcto_present_no_finding(self):
        """Present nosniff suppresses the finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "X-Content-Type-Options": "nosniff",
        })
        findings = self._checker().check("http://example.com", resp)
        titles = [f.title for f in findings]
        assert not any("X-Content-Type-Options" in t for t in titles)

    def test_missing_hsts_on_https(self):
        """Missing HSTS on HTTPS produces a medium finding."""
        resp = _make_response(headers={"content-type": "text/html"})
        findings = self._checker().check("https://example.com", resp)
        hsts = [f for f in findings if "Strict-Transport" in f.title]
        assert len(hsts) >= 1
        assert hsts[0].severity == SeverityLevel.MEDIUM

    def test_no_hsts_finding_on_http(self):
        """HSTS check is skipped for HTTP pages."""
        resp = _make_response(headers={"content-type": "text/html"})
        findings = self._checker().check("http://example.com", resp)
        assert not any("Strict-Transport" in f.title for f in findings)

    def test_server_version_leak(self):
        """Server header with version info produces info finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "Server": "Apache/2.4.51 (Ubuntu)",
        })
        findings = self._checker().check("http://example.com", resp)
        server_findings = [f for f in findings if "Server" in f.title]
        assert len(server_findings) >= 1
        assert server_findings[0].severity == SeverityLevel.INFO

    def test_x_powered_by_leak(self):
        """X-Powered-By header produces info finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "X-Powered-By": "Express",
        })
        findings = self._checker().check("http://example.com", resp)
        assert any("Powered-By" in f.title for f in findings)

    def test_cookie_without_httponly(self):
        """Set-Cookie without HttpOnly produces finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "set-cookie": "session=abc123; Path=/",
        })
        findings = self._checker().check("http://example.com", resp)
        assert any("HttpOnly" in f.title for f in findings)

    def test_cookie_without_secure_on_https(self):
        """Set-Cookie without Secure on HTTPS produces finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "set-cookie": "session=abc123; Path=/; HttpOnly",
        })
        findings = self._checker().check("https://example.com", resp)
        assert any("Secure" in f.title for f in findings)

    def test_secure_cookie_no_finding(self):
        """Cookie with both flags produces no cookie finding."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "set-cookie": "session=abc123; Path=/; HttpOnly; Secure",
        })
        findings = self._checker().check("https://example.com", resp)
        assert not any("HttpOnly" in f.title for f in findings)
        assert not any("Secure Flag" in f.title for f in findings)

    def test_fully_secured_headers(self):
        """Page with all security headers produces minimal findings."""
        resp = _make_response(headers={
            "content-type": "text/html",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        findings = self._checker().check("https://example.com", resp)
        # Should have zero header findings (no server leak, no cookies)
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════
# Sensitive Data Exposure Tests
# ═══════════════════════════════════════════════════════════════════


class TestSensitiveDataChecker:
    """Test passive sensitive data exposure detection."""

    def _checker(self) -> SensitiveDataChecker:
        return SensitiveDataChecker()

    def test_detect_aws_key(self):
        """AWS access key pattern is detected."""
        resp = _make_response(text="key: AKIAIOSFODNN7EXAMPLE")
        findings = self._checker().check("http://example.com", resp)
        assert any("AWS" in f.title for f in findings)
        assert any(f.severity == SeverityLevel.CRITICAL for f in findings)

    def test_detect_private_key(self):
        """PEM private key header is detected."""
        resp = _make_response(
            text="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...",
        )
        findings = self._checker().check("http://example.com", resp)
        assert any("Private Key" in f.title for f in findings)

    def test_detect_jwt_token(self):
        """JWT token is detected."""
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        resp = _make_response(text=f"token: {jwt}")
        findings = self._checker().check("http://example.com", resp)
        assert any("JWT" in f.title for f in findings)

    def test_detect_python_traceback(self):
        """Python stack trace is detected."""
        resp = _make_response(
            text="Traceback (most recent call last):\n  File \"app.py\", line 42",
        )
        findings = self._checker().check("http://example.com", resp)
        assert any("Python" in f.title or "Stack Trace" in f.title for f in findings)

    def test_detect_java_exception(self):
        """Java exception is detected."""
        resp = _make_response(
            text="java.lang.NullPointerException at com.app.Main(Main.java:15)",
        )
        findings = self._checker().check("http://example.com", resp)
        assert any("Java" in f.title for f in findings)

    def test_detect_db_connection_string(self):
        """Database connection string is detected."""
        resp = _make_response(
            text="DB: postgresql://admin:secret@db.internal:5432/mydb",
        )
        findings = self._checker().check("http://example.com", resp)
        assert any("Database" in f.title or "Connection" in f.title for f in findings)

    def test_detect_github_token(self):
        """GitHub personal access token is detected."""
        resp = _make_response(
            text="token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234",
        )
        findings = self._checker().check("http://example.com", resp)
        assert any("GitHub" in f.title for f in findings)

    def test_clean_response_no_findings(self):
        """Normal HTML response has no exposure findings."""
        resp = _make_response(
            text="<html><body>Welcome to our safe application.</body></html>",
        )
        findings = self._checker().check("http://example.com", resp)
        assert len(findings) == 0

    def test_email_below_confidence_threshold(self):
        """Email pattern is below default 0.5 confidence threshold."""
        resp = _make_response(text="Contact us at support@example.com")
        checker = SensitiveDataChecker(min_confidence=0.5)
        findings = checker.check("http://example.com", resp)
        # Email confidence is 0.4, below 0.5 threshold
        assert not any("Email" in f.title for f in findings)


# ═══════════════════════════════════════════════════════════════════
# Engine Passive Integration Tests
# ═══════════════════════════════════════════════════════════════════


class TestEnginePassiveIntegration:
    """Test that the engine runs passive detectors on every page."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_passive_checks_run_on_fuzz_endpoint(self):
        """fuzz_endpoint auto-runs passive header/exposure checks."""
        respx.get("http://testapp.local/page").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Normal page</body></html>",
                headers={"content-type": "text/html"},
                # No security headers at all
            ),
        )

        config = _make_config()
        endpoint = Endpoint(url="http://testapp.local/page", method="GET")

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            findings = await engine.fuzz_endpoint(endpoint, [])

        # Should have found missing CSP, XFO, XCTO at minimum
        titles = [f.title for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)

    @respx.mock
    @pytest.mark.asyncio
    async def test_passive_checks_detect_exposure(self):
        """Passive checks detect sensitive data in response."""
        respx.get("http://testapp.local/debug").mock(
            return_value=httpx.Response(
                200,
                text="Debug: AKIAIOSFODNN7EXAMPLE key leaked",
                headers={"content-type": "text/html"},
            ),
        )

        config = _make_config()
        endpoint = Endpoint(url="http://testapp.local/debug", method="GET")

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            findings = await engine.fuzz_endpoint(endpoint, [])

        assert any("AWS" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_run_passive_checks_standalone(self):
        """run_passive_checks can be called independently."""
        respx.get("http://testapp.local/api").mock(
            return_value=httpx.Response(
                200,
                text="Traceback (most recent call last):\n  File ...",
                headers={
                    "content-type": "text/html",
                    "Server": "Apache/2.4.51",
                },
            ),
        )

        config = _make_config()
        endpoint = Endpoint(url="http://testapp.local/api", method="GET")

        async with HttpClient(timeout=5) as client:
            engine = FuzzEngine(http_client=client, config=config)
            findings = await engine.run_passive_checks(endpoint)

        assert any("Server" in f.title for f in findings)
        assert any("Python" in f.title or "Stack Trace" in f.title for f in findings)
