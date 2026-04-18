"""Tests for the vulnerability analyzer module.

Covers:
- VulnClassifier: classification of all template IDs, unknown templates
- EnrichedFinding: serialization, field defaults
- Prioritizer: correct sort order by severity/CVSS/difficulty/URL
- Aggregator: severity distribution, OWASP grouping, risk score, coverage
- Response analyzer: comprehensive error signature matching
"""

from __future__ import annotations

import pytest

from sentinal_fuzz.analyzer.aggregator import AnalysisReport, aggregate
from sentinal_fuzz.analyzer.classifier import (
    VULN_KNOWLEDGE_BASE,
    EnrichedFinding,
    VulnClassifier,
)
from sentinal_fuzz.analyzer.prioritizer import prioritize
from sentinal_fuzz.analyzer.response import ERROR_SIGNATURES, ResponseAnalyzer
from sentinal_fuzz.core.models import Finding, SeverityLevel


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════


def _make_finding(
    template_id: str = "xss-reflected",
    url: str = "http://test.local/page",
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = 0.8,
    parameter: str = "query:q",
    payload: str = "test",
) -> Finding:
    return Finding(
        title="Test Finding",
        severity=severity,
        url=url,
        parameter=parameter,
        payload=payload,
        confidence=confidence,
        template_id=template_id,
    )


def _make_enriched(
    template_id: str = "xss-reflected",
    url: str = "http://test.local/page",
    severity: SeverityLevel = SeverityLevel.HIGH,
    cvss_score: float = 6.1,
    exploit_difficulty: str = "easy",
    confidence: float = 0.8,
    owasp_category: str = "A03:2021 – Injection",
    cwe_id: str = "CWE-79",
) -> EnrichedFinding:
    return EnrichedFinding(
        title="Test Finding",
        severity=severity,
        url=url,
        confidence=confidence,
        template_id=template_id,
        cvss_score=cvss_score,
        exploit_difficulty=exploit_difficulty,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
    )


# ═══════════════════════════════════════════════════════════════════
# VulnClassifier Tests
# ═══════════════════════════════════════════════════════════════════


class TestVulnClassifier:
    """Test the VulnClassifier classification logic."""

    def test_classify_xss_reflected(self):
        """XSS finding gets correct CVSS, CWE, and OWASP."""
        classifier = VulnClassifier()
        finding = _make_finding(template_id="xss-reflected")
        enriched = classifier.classify(finding)

        assert enriched.cvss_score == 6.1
        assert enriched.cwe_id == "CWE-79"
        assert "Injection" in enriched.owasp_category
        assert enriched.exploit_difficulty == "easy"
        assert len(enriched.remediation_steps) >= 3
        assert enriched.code_example_fix != ""
        assert "session cookies" in enriched.business_impact.lower() or \
               "account takeover" in enriched.business_impact.lower()

    def test_classify_sqli_error(self):
        """SQLi error-based finding gets correct scores."""
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="sqli-error", severity=SeverityLevel.CRITICAL),
        )

        assert enriched.cvss_score == 8.6
        assert enriched.cwe_id == "CWE-89"
        assert "parameterised" in enriched.remediation_steps[0].lower() or \
               "prepared" in enriched.remediation_steps[0].lower()

    def test_classify_sqli_time(self):
        """SQLi time-based finding gets correct scores."""
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="sqli-time", severity=SeverityLevel.CRITICAL),
        )

        assert enriched.cvss_score == 8.6
        assert enriched.cwe_id == "CWE-89"
        assert enriched.exploit_difficulty == "medium"

    def test_classify_ssrf(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="ssrf-basic", severity=SeverityLevel.HIGH),
        )

        assert enriched.cvss_score == 7.5
        assert enriched.cwe_id == "CWE-918"
        assert "SSRF" in enriched.owasp_category or "Request Forgery" in enriched.owasp_category

    def test_classify_ssti(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="ssti-basic", severity=SeverityLevel.CRITICAL),
        )

        assert enriched.cvss_score == 9.8
        assert enriched.cwe_id == "CWE-1336"
        assert "remote code execution" in enriched.business_impact.lower() or \
               "arbitrary code" in enriched.business_impact.lower()

    def test_classify_path_traversal(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="path-traversal", severity=SeverityLevel.HIGH),
        )

        assert enriched.cvss_score == 7.5
        assert enriched.cwe_id == "CWE-22"

    def test_classify_open_redirect(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="open-redirect", severity=SeverityLevel.MEDIUM),
        )

        assert enriched.cvss_score == 4.7
        assert enriched.cwe_id == "CWE-601"

    def test_classify_security_headers(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="security-headers", severity=SeverityLevel.LOW),
        )

        assert enriched.cvss_score == 2.0
        assert enriched.cwe_id == "CWE-693"
        assert "Misconfiguration" in enriched.owasp_category

    def test_classify_sensitive_exposure(self):
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="sensitive-exposure", severity=SeverityLevel.MEDIUM),
        )

        assert enriched.cvss_score == 5.3
        assert enriched.cwe_id == "CWE-200"

    def test_classify_unknown_template(self):
        """Unknown template ID returns enriched finding with defaults."""
        classifier = VulnClassifier()
        enriched = classifier.classify(
            _make_finding(template_id="unknown-vuln"),
        )

        assert enriched.cvss_score == 0.0
        assert enriched.cwe_id == ""
        assert enriched.remediation_steps == []
        assert enriched.template_id == "unknown-vuln"

    def test_classify_preserves_finding_fields(self):
        """All original Finding fields are preserved in EnrichedFinding."""
        finding = _make_finding(
            template_id="xss-reflected",
            url="http://example.com/search",
            parameter="query:term",
            payload="<script>alert(1)</script>",
        )
        finding.evidence = "word match: <script>"
        finding.confidence = 0.85

        classifier = VulnClassifier()
        enriched = classifier.classify(finding)

        assert enriched.url == "http://example.com/search"
        assert enriched.parameter == "query:term"
        assert enriched.payload == "<script>alert(1)</script>"
        assert enriched.evidence == "word match: <script>"
        assert enriched.confidence == 0.85
        assert enriched.id == finding.id

    def test_classify_all(self):
        """classify_all processes a list of findings."""
        classifier = VulnClassifier()
        findings = [
            _make_finding(template_id="xss-reflected"),
            _make_finding(template_id="sqli-error"),
            _make_finding(template_id="ssrf-basic"),
        ]
        enriched = classifier.classify_all(findings)
        assert len(enriched) == 3
        assert enriched[0].cwe_id == "CWE-79"
        assert enriched[1].cwe_id == "CWE-89"
        assert enriched[2].cwe_id == "CWE-918"


# ═══════════════════════════════════════════════════════════════════
# Knowledge Base Completeness Tests
# ═══════════════════════════════════════════════════════════════════


class TestKnowledgeBase:
    """Ensure the knowledge base covers all expected templates."""

    EXPECTED_TEMPLATE_IDS = [
        "xss-reflected",
        "sqli-error",
        "sqli-time",
        "ssrf-basic",
        "ssti-basic",
        "path-traversal",
        "open-redirect",
        "security-headers",
        "sensitive-exposure",
    ]

    def test_all_templates_covered(self):
        for tid in self.EXPECTED_TEMPLATE_IDS:
            assert tid in VULN_KNOWLEDGE_BASE, f"Missing KB entry: {tid}"

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_entry_has_required_fields(self, template_id: str):
        entry = VULN_KNOWLEDGE_BASE[template_id]
        assert "cvss_score" in entry
        assert "cvss_vector" in entry
        assert "cwe_id" in entry
        assert "cwe_name" in entry
        assert "owasp_category" in entry
        assert "business_impact" in entry
        assert "remediation_steps" in entry
        assert "code_example_fix" in entry
        assert "exploit_difficulty" in entry

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_cvss_score_valid(self, template_id: str):
        score = VULN_KNOWLEDGE_BASE[template_id]["cvss_score"]
        assert 0.0 <= score <= 10.0

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_cvss_vector_format(self, template_id: str):
        vector = VULN_KNOWLEDGE_BASE[template_id]["cvss_vector"]
        assert vector.startswith("CVSS:3.1/")

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_cwe_format(self, template_id: str):
        cwe = VULN_KNOWLEDGE_BASE[template_id]["cwe_id"]
        assert cwe.startswith("CWE-")

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_remediation_steps_not_empty(self, template_id: str):
        steps = VULN_KNOWLEDGE_BASE[template_id]["remediation_steps"]
        assert len(steps) >= 3

    @pytest.mark.parametrize("template_id", EXPECTED_TEMPLATE_IDS)
    def test_exploit_difficulty_valid(self, template_id: str):
        diff = VULN_KNOWLEDGE_BASE[template_id]["exploit_difficulty"]
        assert diff in ("easy", "medium", "hard")


# ═══════════════════════════════════════════════════════════════════
# EnrichedFinding Tests
# ═══════════════════════════════════════════════════════════════════


class TestEnrichedFinding:
    """Test EnrichedFinding serialization and defaults."""

    def test_to_dict(self):
        enriched = _make_enriched()
        d = enriched.to_dict()
        assert d["cvss_score"] == 6.1
        assert d["cwe_id"] == "CWE-79"
        assert d["exploit_difficulty"] == "easy"
        assert "severity" in d
        assert "timestamp" in d

    def test_default_fields(self):
        enriched = EnrichedFinding(
            title="Test",
            severity=SeverityLevel.INFO,
            url="http://test.local",
        )
        assert enriched.cvss_score == 0.0
        assert enriched.exploit_difficulty == "medium"
        assert enriched.requires_auth is False
        assert enriched.remediation_steps == []


# ═══════════════════════════════════════════════════════════════════
# Prioritizer Tests
# ═══════════════════════════════════════════════════════════════════


class TestPrioritizer:
    """Test the finding prioritizer sort order."""

    def test_empty_list(self):
        assert prioritize([]) == []

    def test_severity_order(self):
        """Critical findings should come before High."""
        critical = _make_enriched(severity=SeverityLevel.CRITICAL, cvss_score=9.8)
        high = _make_enriched(severity=SeverityLevel.HIGH, cvss_score=7.5)
        low = _make_enriched(severity=SeverityLevel.LOW, cvss_score=2.0)

        result = prioritize([low, high, critical])
        assert result[0].severity == SeverityLevel.CRITICAL
        assert result[1].severity == SeverityLevel.HIGH
        assert result[2].severity == SeverityLevel.LOW

    def test_cvss_order_within_severity(self):
        """Within same severity, higher CVSS comes first."""
        high_9 = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=8.6,
            url="http://a.com",
        )
        high_7 = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=7.5,
            url="http://a.com",
        )

        result = prioritize([high_7, high_9])
        assert result[0].cvss_score == 8.6
        assert result[1].cvss_score == 7.5

    def test_exploit_difficulty_order(self):
        """Easy-to-exploit vulns come before hard ones (same severity+CVSS)."""
        easy = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=7.5,
            exploit_difficulty="easy", url="http://a.com",
        )
        hard = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=7.5,
            exploit_difficulty="hard", url="http://a.com",
        )

        result = prioritize([hard, easy])
        assert result[0].exploit_difficulty == "easy"
        assert result[1].exploit_difficulty == "hard"

    def test_url_grouping(self):
        """Same-URL findings are grouped together (alphabetical)."""
        f1 = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=7.5,
            url="http://z.com/page",
        )
        f2 = _make_enriched(
            severity=SeverityLevel.HIGH, cvss_score=7.5,
            url="http://a.com/page",
        )

        result = prioritize([f1, f2])
        assert result[0].url == "http://a.com/page"
        assert result[1].url == "http://z.com/page"

    def test_composite_sort(self):
        """Full composite sort with mixed severities."""
        findings = [
            _make_enriched(severity=SeverityLevel.LOW, cvss_score=2.0),
            _make_enriched(severity=SeverityLevel.CRITICAL, cvss_score=9.8),
            _make_enriched(severity=SeverityLevel.MEDIUM, cvss_score=4.7),
            _make_enriched(severity=SeverityLevel.HIGH, cvss_score=8.6),
            _make_enriched(severity=SeverityLevel.INFO, cvss_score=0.0),
        ]
        result = prioritize(findings)
        severities = [f.severity for f in result]
        assert severities == [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]


# ═══════════════════════════════════════════════════════════════════
# Aggregator Tests
# ═══════════════════════════════════════════════════════════════════


class TestAggregator:
    """Test the findings aggregator."""

    def test_empty_list(self):
        report = aggregate([])
        assert report.total_findings == 0
        assert report.risk_score == 0.0

    def test_severity_distribution(self):
        findings = [
            _make_enriched(severity=SeverityLevel.CRITICAL),
            _make_enriched(severity=SeverityLevel.CRITICAL),
            _make_enriched(severity=SeverityLevel.HIGH),
            _make_enriched(severity=SeverityLevel.LOW),
        ]
        report = aggregate(findings)
        assert report.by_severity["Critical"] == 2
        assert report.by_severity["High"] == 1
        assert report.by_severity["Low"] == 1

    def test_highest_severity(self):
        findings = [
            _make_enriched(severity=SeverityLevel.MEDIUM),
            _make_enriched(severity=SeverityLevel.HIGH),
            _make_enriched(severity=SeverityLevel.LOW),
        ]
        report = aggregate(findings)
        assert report.highest_severity == "High"

    def test_owasp_distribution(self):
        findings = [
            _make_enriched(owasp_category="A03:2021 – Injection"),
            _make_enriched(owasp_category="A03:2021 – Injection"),
            _make_enriched(owasp_category="A05:2021 – Security Misconfiguration"),
        ]
        report = aggregate(findings)
        assert report.by_owasp["A03:2021 – Injection"] == 2
        assert report.by_owasp["A05:2021 – Security Misconfiguration"] == 1

    def test_unique_endpoints(self):
        findings = [
            _make_enriched(url="http://test.local/page1?q=1"),
            _make_enriched(url="http://test.local/page1?q=2"),     # Same path, diff query
            _make_enriched(url="http://test.local/page2"),
        ]
        report = aggregate(findings)
        assert report.unique_endpoints_affected == 2  # page1 + page2

    def test_risk_score_nonzero(self):
        findings = [
            _make_enriched(severity=SeverityLevel.CRITICAL),
            _make_enriched(severity=SeverityLevel.HIGH),
        ]
        report = aggregate(findings)
        assert report.risk_score > 0

    def test_risk_score_capped_at_100(self):
        """Risk score should never exceed 100."""
        findings = [
            _make_enriched(severity=SeverityLevel.CRITICAL) for _ in range(20)
        ]
        report = aggregate(findings)
        assert report.risk_score <= 100.0

    def test_scan_coverage(self):
        findings = [
            _make_enriched(url="http://test.local/page1"),
            _make_enriched(url="http://test.local/page2"),
        ]
        report = aggregate(findings, total_endpoints=10)
        assert report.scan_coverage == 20.0  # 2/10 * 100

    def test_scan_coverage_zero_endpoints(self):
        report = aggregate([], total_endpoints=0)
        assert report.scan_coverage == 0.0

    def test_avg_cvss(self):
        findings = [
            _make_enriched(cvss_score=6.0),
            _make_enriched(cvss_score=8.0),
        ]
        report = aggregate(findings)
        assert report.avg_cvss == 7.0

    def test_to_dict(self):
        report = AnalysisReport(total_findings=5, risk_score=42.5)
        d = report.to_dict()
        assert d["total_findings"] == 5
        assert d["risk_score"] == 42.5


# ═══════════════════════════════════════════════════════════════════
# Error Signature Tests
# ═══════════════════════════════════════════════════════════════════


class TestErrorSignatures:
    """Test the comprehensive error signature database."""

    def test_mysql_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "You have an error in your SQL syntax near 'test'"
        )
        assert result.matched is True

    def test_mysql_fetch_array_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "Warning: mysql_fetch_array() expects parameter"
        )
        assert result.matched is True

    def test_postgresql_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "ERROR: unterminated quoted string at position 42"
        )
        assert result.matched is True

    def test_postgresql_pg_query_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("Warning: pg_query() failed")
        assert result.matched is True

    def test_mssql_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "Unclosed quotation mark after the character string 'test'"
        )
        assert result.matched is True

    def test_mssql_native_client_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "Microsoft SQL Native Client error '80040e14'"
        )
        assert result.matched is True

    def test_oracle_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("ORA-01756: quoted string not terminated")
        assert result.matched is True

    def test_oracle_generic_code_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("ORA-00933: SQL command not properly ended")
        assert result.matched is True

    def test_sqlite_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("SQLite3::query(): unable to prepare")
        assert result.matched is True

    def test_sqlite_syntax_error_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak('near "UNION": syntax error')
        assert result.matched is True

    def test_php_warning_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("Fatal error: Uncaught Exception in /var/www")
        assert result.matched is True

    def test_python_traceback_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("Traceback (most recent call last)")
        assert result.matched is True

    def test_java_exception_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("java.sql.SQLException: wrong number of parameters")
        assert result.matched is True

    def test_ognl_exception_detected(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak("OgnlException: target class not found")
        assert result.matched is True

    def test_clean_response_no_detection(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.error_leak(
            "<html><body>Welcome to our safe page</body></html>"
        )
        assert result.matched is False

    def test_error_signatures_dict_has_all_categories(self):
        """ERROR_SIGNATURES should cover all documented databases."""
        expected = [
            "mysql", "postgresql", "mssql", "oracle", "sqlite",
            "sql_generic", "php", "python", "java", "dotnet",
            "ruby", "info_leak",
        ]
        for category in expected:
            assert category in ERROR_SIGNATURES, f"Missing category: {category}"
            assert len(ERROR_SIGNATURES[category]) >= 3, (
                f"Category '{category}' has too few patterns"
            )

    def test_info_leak_detection(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.info_leak("Stack trace: at com.example.MyClass")
        assert result.matched is True

    def test_info_leak_clean_response(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.info_leak("Everything is fine. No errors here.")
        assert result.matched is False
