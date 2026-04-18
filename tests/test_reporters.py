"""Tests for the Sentinal-Fuzz report generation system.

Covers:
- JSON reporter: serialization, re-loading, round-trip
- HTML reporter: structure, self-containment, finding cards
- SARIF reporter: valid JSON, schema structure, rules/results
- Terminal reporter: output without crashing (Rich + fallback)
- Reporter factory: format dispatch, unsupported format error
- Cross-format: JSON → HTML re-generation
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta

import pytest

from sentinal_fuzz.core.models import (
    Endpoint,
    Finding,
    HttpExchange,
    ScanResult,
    ScanStats,
    SeverityLevel,
)
from sentinal_fuzz.reporter.html_reporter import HtmlReporter
from sentinal_fuzz.reporter.json_reporter import JsonReporter
from sentinal_fuzz.reporter.reporter_factory import (
    UnsupportedFormatError,
    get_all_reporters,
    get_reporter,
)
from sentinal_fuzz.reporter.sarif_reporter import SarifReporter
from sentinal_fuzz.reporter.terminal_reporter import TerminalReporter


# ── Test fixtures ──────────────────────────────────────────────────


def _make_scan_result(
    *,
    num_findings: int = 3,
    num_endpoints: int = 5,
) -> ScanResult:
    """Build a realistic ScanResult for testing."""
    start = datetime(2026, 4, 3, 10, 0, 0)
    end = start + timedelta(seconds=12.5)

    endpoints = []
    for i in range(num_endpoints):
        endpoints.append(
            Endpoint(
                url=f"http://testapp.local/page{i}",
                method="GET" if i % 2 == 0 else "POST",
                params={"id": str(i), "q": "test"} if i < 3 else {},
                forms=[{"name": "username", "type": "text", "value": ""}] if i % 2 != 0 else [],
                source="crawl",
            )
        )

    findings = []
    finding_templates = [
        {
            "title": "SQL Injection — Error-Based",
            "severity": SeverityLevel.CRITICAL,
            "url": "http://testapp.local/page0",
            "parameter": "query:id",
            "payload": "' OR 1=1--",
            "evidence": "regex match: SQL syntax error near MySQL",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "template_id": "sqli-error",
            "remediation": "Use parameterised queries for all database access. Never concatenate user input into SQL strings.",
            "confidence": 0.9,
        },
        {
            "title": "Reflected Cross-Site Scripting",
            "severity": SeverityLevel.HIGH,
            "url": "http://testapp.local/page1",
            "parameter": "query:q",
            "payload": "<script>alert(1)</script>",
            "evidence": "word match: <script>alert(1)</script>",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "template_id": "xss-reflected",
            "remediation": "HTML-encode all user-supplied data before rendering.",
            "confidence": 0.6,
        },
        {
            "title": "Missing Security Headers",
            "severity": SeverityLevel.LOW,
            "url": "http://testapp.local/page0",
            "parameter": "",
            "payload": "(passive check)",
            "evidence": "header X-Frame-Options absent",
            "cwe": "CWE-693",
            "owasp": "A05:2021-Security Misconfiguration",
            "template_id": "security-headers",
            "remediation": "Add X-Frame-Options: DENY header.",
            "confidence": 1.0,
        },
    ]

    for i in range(min(num_findings, len(finding_templates))):
        tmpl = finding_templates[i]
        req = HttpExchange(
            method="GET",
            url=tmpl["url"],
            request_headers={"User-Agent": "Sentinal-Fuzz/0.1.0"},
            request_body=None,
            status_code=200,
            response_headers={"content-type": "text/html"},
            response_body="<html><body>Test response</body></html>",
            elapsed_ms=42.5,
        )
        findings.append(
            Finding(
                title=tmpl["title"],
                severity=tmpl["severity"],
                url=tmpl["url"],
                parameter=tmpl["parameter"],
                payload=tmpl["payload"],
                evidence=tmpl["evidence"],
                request=req,
                response=f"HTTP 200\n<html><body>{tmpl['evidence']}</body></html>",
                cwe=tmpl["cwe"],
                owasp=tmpl["owasp"],
                remediation=tmpl["remediation"],
                confidence=tmpl["confidence"],
                template_id=tmpl["template_id"],
                id=f"finding-{i:04d}",
                timestamp=start,
            )
        )

    stats = ScanStats(
        total_requests=150,
        urls_crawled=20,
        endpoints_found=num_endpoints,
        templates_run=9,
        findings_by_severity={
            "critical": sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
            "high": sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
            "medium": sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM),
            "low": sum(1 for f in findings if f.severity == SeverityLevel.LOW),
            "info": sum(1 for f in findings if f.severity == SeverityLevel.INFO),
        },
        requests_per_second=12.0,
    )

    return ScanResult(
        target="http://testapp.local",
        start_time=start,
        end_time=end,
        endpoints=endpoints,
        findings=findings,
        stats=stats,
        scan_id="test-scan-0001",
        scan_profile="standard",
        scanner_version="0.1.0",
    )


def _make_empty_result() -> ScanResult:
    """Build a ScanResult with no findings."""
    return _make_scan_result(num_findings=0, num_endpoints=2)


# ═══════════════════════════════════════════════════════════════════
# JSON Reporter Tests
# ═══════════════════════════════════════════════════════════════════


class TestJsonReporter:
    """Test the JSON report generator."""

    def test_generates_valid_json(self):
        """JSON output should be valid, parseable JSON."""
        result = _make_scan_result()
        report_dict = JsonReporter.build_report_dict(result)
        json_str = json.dumps(report_dict, default=str)
        loaded = json.loads(json_str)
        assert isinstance(loaded, dict)

    def test_json_has_required_sections(self):
        """JSON must include metadata, summary, endpoints, findings, stats."""
        result = _make_scan_result()
        data = JsonReporter.build_report_dict(result)
        assert "schema_version" in data
        assert "metadata" in data
        assert "summary" in data
        assert "endpoints" in data
        assert "findings" in data
        assert "stats" in data

    def test_json_metadata_correct(self):
        """Metadata should contain scan_id, target, timestamps."""
        result = _make_scan_result()
        data = JsonReporter.build_report_dict(result)
        meta = data["metadata"]
        assert meta["scan_id"] == "test-scan-0001"
        assert meta["target"] == "http://testapp.local"
        assert meta["scanner_version"] == "0.1.0"
        assert "start_time" in meta
        assert "duration_seconds" in meta

    def test_json_findings_count_matches(self):
        """Number of findings in JSON should match the result."""
        result = _make_scan_result(num_findings=3)
        data = JsonReporter.build_report_dict(result)
        assert len(data["findings"]) == 3
        assert data["summary"]["total_findings"] == 3

    def test_json_severity_counts(self):
        """Severity counts should be accurate."""
        result = _make_scan_result(num_findings=3)
        data = JsonReporter.build_report_dict(result)
        counts = data["summary"]["severity_counts"]
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["low"] == 1

    def test_json_endpoints_serialized(self):
        """All endpoints should be serialized with their params."""
        result = _make_scan_result(num_endpoints=5)
        data = JsonReporter.build_report_dict(result)
        assert len(data["endpoints"]) == 5
        assert "url" in data["endpoints"][0]
        assert "injectable_params" in data["endpoints"][0]

    def test_json_finding_has_request_evidence(self):
        """Findings with requests should include request_evidence."""
        result = _make_scan_result(num_findings=1)
        data = JsonReporter.build_report_dict(result)
        finding = data["findings"][0]
        assert finding["request_evidence"] is not None
        assert "method" in finding["request_evidence"]
        assert "status_code" in finding["request_evidence"]

    def test_json_risk_score_range(self):
        """Risk score should be between 0 and 100."""
        result = _make_scan_result()
        data = JsonReporter.build_report_dict(result)
        assert 0 <= data["summary"]["risk_score"] <= 100

    def test_json_most_critical_finding(self):
        """Most critical finding should be the highest severity."""
        result = _make_scan_result()
        data = JsonReporter.build_report_dict(result)
        mc = data["summary"]["most_critical"]
        assert mc is not None
        assert mc["severity"] == "critical"

    def test_json_empty_result(self):
        """Empty result should produce valid JSON with zero findings."""
        result = _make_empty_result()
        data = JsonReporter.build_report_dict(result)
        assert data["summary"]["total_findings"] == 0
        assert data["summary"]["most_critical"] is None
        assert data["summary"]["risk_score"] == 0

    def test_json_writes_file(self):
        """Reporter should write a .json file to disk."""
        result = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = JsonReporter(output_dir=tmpdir)
            filepath = reporter.generate(result)
            assert os.path.isfile(filepath)
            assert filepath.endswith(".json")
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert data["metadata"]["target"] == "http://testapp.local"

    def test_json_roundtrip_reload(self):
        """JSON output should be re-loadable to access all fields."""
        result = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = JsonReporter(output_dir=tmpdir)
            filepath = reporter.generate(result)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            # Verify we can access all the critical data
            assert len(data["findings"]) == 3
            assert data["findings"][0]["title"] == "SQL Injection — Error-Based"
            assert data["findings"][0]["cwe"] == "CWE-89"
            assert data["endpoints"][0]["url"] == "http://testapp.local/page0"


# ═══════════════════════════════════════════════════════════════════
# HTML Reporter Tests
# ═══════════════════════════════════════════════════════════════════


class TestHtmlReporter:
    """Test the HTML report generator."""

    def test_html_is_valid_document(self):
        """HTML should be a complete document with head and body."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "<!DOCTYPE html>" in html_content
        assert "<html" in html_content
        assert "<head>" in html_content
        assert "<body>" in html_content
        assert "</html>" in html_content

    def test_html_is_self_contained(self):
        """HTML must have no external CSS/JS CDN references."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "https://cdn" not in html_content
        assert "https://unpkg" not in html_content
        assert "https://cdnjs" not in html_content
        assert "<style>" in html_content  # CSS is inlined

    def test_html_has_header(self):
        """HTML should contain the project name and target."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "Sentinal-Fuzz" in html_content
        assert "testapp.local" in html_content

    def test_html_has_executive_summary(self):
        """HTML should contain an executive summary section."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "Executive Summary" in html_content
        assert "Risk Score" in html_content

    def test_html_has_finding_cards(self):
        """HTML should contain finding cards with severity badges."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "finding-card" in html_content
        assert "severity-badge" in html_content
        assert "SQL Injection" in html_content
        assert "Cross-Site Scripting" in html_content

    def test_html_has_plain_english_sections(self):
        """Each finding should have What/How/Fix sections."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "What This Means" in html_content
        assert "How an Attacker Could Use This" in html_content
        assert "How to Fix It" in html_content

    def test_html_has_technical_details(self):
        """Finding cards should have collapsible technical details."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "Technical Details" in html_content
        assert "CWE-89" in html_content

    def test_html_has_endpoint_map(self):
        """HTML should include the endpoint map table."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "Endpoint Map" in html_content
        assert "endpoints-table" in html_content

    def test_html_has_scan_stats(self):
        """HTML should include scan statistics."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "Scan Statistics" in html_content
        assert "150" in html_content  # total requests

    def test_html_dark_theme(self):
        """HTML should use a dark background theme."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "#0f1117" in html_content  # Dark background color

    def test_html_print_media_query(self):
        """HTML should include print-friendly CSS."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "@media print" in html_content

    def test_html_responsive(self):
        """HTML should include responsive CSS."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "@media (max-width:" in html_content
        assert "viewport" in html_content

    def test_html_empty_result(self):
        """Empty result should show 'no vulnerabilities' message."""
        result = _make_empty_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "No vulnerabilities found" in html_content or "no vulnerabilities" in html_content

    def test_html_writes_file(self):
        """Reporter should write a .html file to disk."""
        result = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = HtmlReporter(output_dir=tmpdir)
            filepath = reporter.generate(result)
            assert os.path.isfile(filepath)
            assert filepath.endswith(".html")

    def test_html_has_donut_chart(self):
        """HTML should contain a CSS donut chart."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "donut-chart" in html_content
        assert "conic-gradient" in html_content

    def test_html_findings_sorted_by_severity(self):
        """Findings should be sorted: critical first, info last."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        # Critical (SQLi) should appear before Low (headers)
        sqli_pos = html_content.find("SQL Injection")
        headers_pos = html_content.find("Missing Security Headers")
        assert sqli_pos < headers_pos

    def test_html_uses_details_tags(self):
        """HTML should use <details> tags for collapsible sections."""
        result = _make_scan_result()
        reporter = HtmlReporter(output_dir=".")
        html_content = reporter._render(result)
        assert "<details" in html_content
        assert "<summary" in html_content


# ═══════════════════════════════════════════════════════════════════
# SARIF Reporter Tests
# ═══════════════════════════════════════════════════════════════════


class TestSarifReporter:
    """Test the SARIF 2.1.0 report generator."""

    def test_sarif_is_valid_json(self):
        """SARIF output should be valid JSON."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        json_str = json.dumps(sarif, default=str)
        loaded = json.loads(json_str)
        assert isinstance(loaded, dict)

    def test_sarif_has_correct_version(self):
        """SARIF must declare version 2.1.0."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_schema(self):
        """SARIF must include the $schema field."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_has_runs(self):
        """SARIF must contain a runs array with at least one run."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_info(self):
        """SARIF run must describe the Sentinal-Fuzz tool."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Sentinal-Fuzz"
        assert tool["version"] == "0.1.0"

    def test_sarif_has_rules(self):
        """SARIF should define rules for each unique template."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        rule_ids = {r["id"] for r in rules}
        assert "sqli-error" in rule_ids
        assert "xss-reflected" in rule_ids

    def test_sarif_has_results(self):
        """SARIF should contain one result per finding."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_sarif_result_has_rule_id(self):
        """Each SARIF result should reference a ruleId."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert "ruleId" in r
            assert r["ruleId"]  # Not empty

    def test_sarif_result_has_level(self):
        """Each SARIF result should have a level (error/warning/note)."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert "level" in r
            assert r["level"] in ("error", "warning", "note", "none")

    def test_sarif_result_has_location(self):
        """Each SARIF result should have at least one location."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert "locations" in r
            assert len(r["locations"]) >= 1
            loc = r["locations"][0]
            assert "physicalLocation" in loc

    def test_sarif_has_invocations(self):
        """SARIF run should have invocations with execution info."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_sarif_has_security_severity(self):
        """Rules should have security-severity property for GitHub."""
        result = _make_scan_result()
        sarif = SarifReporter.build_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "security-severity" in rule["properties"]
            severity = float(rule["properties"]["security-severity"])
            assert 0.0 <= severity <= 10.0

    def test_sarif_empty_result(self):
        """Empty scan result should produce valid SARIF with no results."""
        result = _make_empty_result()
        sarif = SarifReporter.build_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_sarif_writes_file(self):
        """Reporter should write a .sarif file to disk."""
        result = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = SarifReporter(output_dir=tmpdir)
            filepath = reporter.generate(result)
            assert os.path.isfile(filepath)
            assert filepath.endswith(".sarif")
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert data["version"] == "2.1.0"


# ═══════════════════════════════════════════════════════════════════
# Terminal Reporter Tests
# ═══════════════════════════════════════════════════════════════════


class TestTerminalReporter:
    """Test the Rich terminal reporter."""

    def test_terminal_does_not_crash(self):
        """Terminal reporter should execute without errors."""
        result = _make_scan_result()
        reporter = TerminalReporter(verbose=False)
        # generate() prints to stdout — just ensure no exception
        filepath = reporter.generate(result)
        assert filepath == ""  # Terminal reporter writes no file

    def test_terminal_verbose_mode(self):
        """Verbose mode should run without errors."""
        result = _make_scan_result()
        reporter = TerminalReporter(verbose=True)
        filepath = reporter.generate(result)
        assert filepath == ""

    def test_terminal_empty_result(self):
        """Empty result should show 'no vulnerabilities' message."""
        result = _make_empty_result()
        reporter = TerminalReporter(verbose=False)
        filepath = reporter.generate(result)
        assert filepath == ""

    def test_terminal_fallback(self, capsys):
        """Fallback output should print a summary."""
        result = _make_scan_result()
        TerminalReporter._print_fallback(result)
        captured = capsys.readouterr()
        assert "Sentinal-Fuzz" in captured.out
        assert "testapp.local" in captured.out


# ═══════════════════════════════════════════════════════════════════
# Reporter Factory Tests
# ═══════════════════════════════════════════════════════════════════


class TestReporterFactory:
    """Test the reporter factory function."""

    def test_get_json_reporter(self):
        """'json' should return a JsonReporter."""
        reporter = get_reporter("json")
        assert isinstance(reporter, JsonReporter)

    def test_get_html_reporter(self):
        """'html' should return an HtmlReporter."""
        reporter = get_reporter("html")
        assert isinstance(reporter, HtmlReporter)

    def test_get_sarif_reporter(self):
        """'sarif' should return a SarifReporter."""
        reporter = get_reporter("sarif")
        assert isinstance(reporter, SarifReporter)

    def test_get_terminal_reporter(self):
        """'terminal' should return a TerminalReporter."""
        reporter = get_reporter("terminal")
        assert isinstance(reporter, TerminalReporter)

    def test_get_all_reporters(self):
        """'all' should return a list of reporters."""
        reporters = get_reporter("all")
        assert isinstance(reporters, list)
        assert len(reporters) >= 3
        types = {type(r).__name__ for r in reporters}
        assert "JsonReporter" in types
        assert "HtmlReporter" in types
        assert "TerminalReporter" in types

    def test_custom_output_dir(self):
        """output_dir parameter should be passed to reporters."""
        reporter = get_reporter("json", output_dir="/custom/path")
        assert reporter.output_dir == "/custom/path"

    def test_unsupported_format_raises(self):
        """Unknown format should raise UnsupportedFormatError."""
        with pytest.raises(UnsupportedFormatError):
            get_reporter("pdf")

    def test_case_insensitive_format(self):
        """Format string should be case-insensitive."""
        reporter = get_reporter("JSON")
        assert isinstance(reporter, JsonReporter)

    def test_get_all_reporters_helper(self):
        """get_all_reporters() should return a list."""
        reporters = get_all_reporters()
        assert isinstance(reporters, list)
        assert len(reporters) >= 3


# ═══════════════════════════════════════════════════════════════════
# Cross-Format Tests
# ═══════════════════════════════════════════════════════════════════


class TestCrossFormat:
    """Test cross-format workflows."""

    def test_json_to_html_regeneration(self):
        """JSON output should contain enough data to regenerate HTML.

        This test verifies the JSON is a faithful representation of
        the scan result that could be used to recreate reports.
        """
        result = _make_scan_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate JSON
            json_reporter = JsonReporter(output_dir=tmpdir)
            json_path = json_reporter.generate(result)

            # Load JSON
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            # Verify JSON has all the data needed for HTML generation
            assert "metadata" in data
            assert "findings" in data
            assert "endpoints" in data
            assert "summary" in data

            # Each finding has the fields HTML needs
            for finding_data in data["findings"]:
                assert "title" in finding_data
                assert "severity" in finding_data
                assert "url" in finding_data
                assert "remediation" in finding_data
                assert "template_id" in finding_data
                assert "cwe" in finding_data

            # Summary has what HTML needs
            assert "risk_score" in data["summary"]
            assert "severity_counts" in data["summary"]

    def test_all_formats_generate_without_error(self):
        """All format reporters should generate without errors."""
        result = _make_scan_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            for fmt in ("json", "html", "sarif"):
                reporter = get_reporter(fmt, output_dir=tmpdir)
                filepath = reporter.generate(result)
                assert os.path.isfile(filepath), f"{fmt} report was not created"

            # Terminal reporter (no file)
            terminal = get_reporter("terminal")
            terminal.generate(result)

    def test_json_finding_ids_match_sarif_rule_ids(self):
        """SARIF rule IDs should correspond to JSON finding template_ids."""
        result = _make_scan_result()
        json_data = JsonReporter.build_report_dict(result)
        sarif_data = SarifReporter.build_sarif(result)

        json_template_ids = {f["template_id"] for f in json_data["findings"]}
        sarif_rule_ids = {r["id"] for r in sarif_data["runs"][0]["tool"]["driver"]["rules"]}

        # All JSON template IDs should correspond to SARIF rules
        assert json_template_ids == sarif_rule_ids
