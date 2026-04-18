"""End-to-end integration tests for Sentinal-Fuzz.

Spins up a local vulnerable test server and runs the complete scan
pipeline against it, asserting that expected vulnerabilities are found.

Requirements:
    - Flask (for the test server)
    - pytest-asyncio (for async test support)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import Finding, SeverityLevel


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vuln_server():
    """Start the vulnerable test server for the test module.

    Yields the base URL (e.g. ``http://127.0.0.1:XXXX``).
    """
    from tests.fixtures.vulnerable_app import run_server

    thread, port = run_server(host="127.0.0.1", port=0)
    base_url = f"http://127.0.0.1:{port}"

    # Extra wait to ensure server is fully ready
    time.sleep(0.3)

    yield base_url

    # Thread is daemonic, will be cleaned up on process exit


@pytest.fixture
def scan_config(vuln_server: str) -> ScanConfig:
    """Build a ScanConfig targeting the vulnerable test server.

    Uses minimal settings for fast testing.
    """
    return ScanConfig(
        target=vuln_server,
        depth=2,
        concurrency=5,
        timeout=10,
        scan_profile="quick",
        output_format="json",
        output_dir="reports/test",
        rate_limit=0,
        follow_redirects=True,
    )


# ── Helpers ───────────────────────────────────────────────────────


def _find_by_title_substr(
    findings: list[Finding],
    substr: str,
) -> list[Finding]:
    """Return findings whose title contains *substr* (case-insensitive)."""
    lower = substr.lower()
    return [f for f in findings if lower in f.title.lower()]


def _find_by_cwe(
    findings: list[Finding],
    cwe: str,
) -> list[Finding]:
    """Return findings matching a CWE identifier."""
    return [f for f in findings if f.cwe == cwe]


# ── Integration Tests ─────────────────────────────────────────────


class TestEndToEndScan:
    """Full end-to-end scan against the vulnerable test server."""

    @pytest.fixture(autouse=True)
    async def _run_scan(self, scan_config: ScanConfig):
        """Run the scan once and store the result for all tests."""
        from sentinal_fuzz.core.scanner import Scanner

        scanner = Scanner(config=scan_config)

        # Collect events for assertion
        self.events: dict[str, list] = {
            "url_found": [],
            "crawl_complete": [],
            "finding": [],
            "scan_complete": [],
        }

        scanner.event_bus.on(
            "url_found",
            lambda url="", **kw: self.events["url_found"].append(url),
        )
        scanner.event_bus.on(
            "crawl_complete",
            lambda endpoints=None, **kw: self.events["crawl_complete"].append(endpoints),
        )
        scanner.event_bus.on(
            "finding",
            lambda finding=None, **kw: self.events["finding"].append(finding),
        )
        scanner.event_bus.on(
            "scan_complete",
            lambda result=None, **kw: self.events["scan_complete"].append(result),
        )

        self.result = await scanner.run()

    def test_scan_completes(self):
        """Scanner.run() should return a ScanResult without error."""
        assert self.result is not None
        assert self.result.target.startswith("http://127.0.0.1:")

    def test_endpoints_discovered(self):
        """Crawler should discover at least 1 endpoint."""
        assert len(self.result.endpoints) >= 1

    def test_findings_not_empty(self):
        """Scanner should find at least one vulnerability."""
        assert len(self.result.findings) > 0

    def test_missing_security_headers_detected(self):
        """Scanner should detect missing security headers (passive check).

        The test server intentionally omits CSP, X-Frame-Options, etc.
        """
        header_findings = [
            f for f in self.result.findings
            if any(
                kw in f.title.lower()
                for kw in [
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "security",
                    "header",
                ]
            )
        ]
        assert len(header_findings) > 0, (
            f"Expected at least one header finding, got: "
            f"{[f.title for f in self.result.findings]}"
        )

    def test_scan_result_has_stats(self):
        """ScanResult should have populated stats."""
        assert self.result.stats.total_requests > 0
        assert self.result.duration_seconds > 0

    def test_scan_result_has_timing(self):
        """ScanResult should have valid start/end times."""
        assert self.result.start_time is not None
        assert self.result.end_time is not None
        assert self.result.end_time >= self.result.start_time

    def test_events_emitted(self):
        """EventBus should have emitted crawl_complete and scan_complete."""
        assert len(self.events["crawl_complete"]) == 1, "crawl_complete should fire once"
        assert len(self.events["scan_complete"]) == 1, "scan_complete should fire once"

    def test_url_found_events(self):
        """EventBus should emit url_found for discovered endpoints."""
        assert len(self.events["url_found"]) >= 1

    def test_findings_have_metadata(self):
        """Each finding should have a title, severity, and URL."""
        for finding in self.result.findings:
            assert finding.title, f"Finding missing title: {finding}"
            assert finding.severity is not None, f"Finding missing severity: {finding}"
            assert finding.url, f"Finding missing URL: {finding}"


class TestScanWithCustomConfig:
    """Tests with varied scan configurations."""

    async def test_quick_profile_works(self, vuln_server: str):
        """Quick profile should complete without errors."""
        from sentinal_fuzz.core.scanner import Scanner

        config = ScanConfig(
            target=vuln_server,
            scan_profile="quick",
            output_format="json",
            output_dir="reports/test",
        )
        scanner = Scanner(config=config)
        result = await scanner.run()
        assert result is not None
        assert len(result.endpoints) >= 1


class TestEventBus:
    """Test the EventBus in isolation."""

    def test_emit_calls_handlers(self):
        """Handlers should be called with keyword arguments."""
        from sentinal_fuzz.core.event_bus import EventBus

        bus = EventBus()
        received: list[dict] = []

        def handler(**kwargs):
            received.append(kwargs)

        bus.on("test_event", handler)
        bus.emit("test_event", foo="bar", count=42)

        assert len(received) == 1
        assert received[0] == {"foo": "bar", "count": 42}

    def test_emit_error_isolation(self):
        """Handler errors should not propagate."""
        from sentinal_fuzz.core.event_bus import EventBus

        bus = EventBus()
        called = []

        def bad_handler(**kwargs):
            raise RuntimeError("boom")

        def good_handler(**kwargs):
            called.append(True)

        bus.on("test", bad_handler)
        bus.on("test", good_handler)

        # Should not raise
        bus.emit("test")

        # Good handler should still be called
        assert len(called) == 1

    def test_off_removes_handler(self):
        """off() should unregister a handler."""
        from sentinal_fuzz.core.event_bus import EventBus

        bus = EventBus()
        called = []

        def handler(**kwargs):
            called.append(True)

        bus.on("test", handler)
        bus.off("test", handler)
        bus.emit("test")

        assert len(called) == 0

    def test_clear_removes_all(self):
        """clear() should remove all handlers."""
        from sentinal_fuzz.core.event_bus import EventBus

        bus = EventBus()
        bus.on("a", lambda **kw: None)
        bus.on("b", lambda **kw: None)

        bus.clear()

        # Emitting should do nothing (no error)
        bus.emit("a")
        bus.emit("b")
