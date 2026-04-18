"""Regression tests for false-positive reduction.

Simulates server behaviours that commonly produce false positives
and verifies that the 3-layer confirmation system correctly rejects
them. No real HTTP servers are needed — all tests use mock Response
objects.

Test scenarios:
1. Server that always shows "syntax error" in footer → must NOT trigger SQLi
2. Server that always takes 4 seconds → must NOT trigger time-based SQLi
3. Server that HTML-escapes all input → must NOT trigger XSS
4. Deduplicator correctly removes redundant findings
5. FalsePositiveFilter rules work independently
6. verify_xss_unescaped correctly identifies script context
"""

from __future__ import annotations

import pytest

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.fuzzer.deduplicator import deduplicate
from sentinal_fuzz.fuzzer.engine import FuzzEngine, _get_part
from sentinal_fuzz.fuzzer.false_positive_filter import (
    FalsePositiveFilter,
    verify_xss_unescaped,
)
from sentinal_fuzz.fuzzer.template_schema import Matcher
from sentinal_fuzz.utils.http import Response


# ═══════════════════════════════════════════════════════════════════
# Helpers — mock response factory
# ═══════════════════════════════════════════════════════════════════

def _make_response(
    text: str = "",
    status_code: int = 200,
    elapsed_ms: float = 100.0,
    headers: dict[str, str] | None = None,
) -> Response:
    """Create a mock Response for testing."""
    return Response(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
        elapsed_ms=elapsed_ms,
        url="http://test.local/page",
    )


def _make_finding(
    template_id: str = "test-template",
    url: str = "http://test.local/page",
    parameter: str = "query:q",
    payload: str = "test-payload",
    evidence: str = "",
    confidence: float = 0.8,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> Finding:
    """Create a mock Finding for testing."""
    return Finding(
        title="Test Finding",
        severity=severity,
        url=url,
        parameter=parameter,
        payload=payload,
        evidence=evidence,
        confidence=confidence,
        template_id=template_id,
    )


# ═══════════════════════════════════════════════════════════════════
# Scenario 1: "syntax error" in footer → NOT SQLi
# ═══════════════════════════════════════════════════════════════════


class TestSyntaxErrorInFooter:
    """Server that always shows 'syntax error' in its footer.

    The word 'SQL syntax' or 'syntax error' appears in every response
    because it's part of the page design, NOT evidence of SQL injection.
    """

    FOOTER_HTML = """
    <html>
    <body>
        <div id="content">Search results for: test</div>
        <footer>
            <p>If you encounter a syntax error, please report it to admin.</p>
        </footer>
    </body>
    </html>
    """

    FUZZED_HTML = """
    <html>
    <body>
        <div id="content">Search results for: ' OR '1'='1</div>
        <footer>
            <p>If you encounter a syntax error, please report it to admin.</p>
        </footer>
    </body>
    </html>
    """

    def test_word_matcher_rejects_baseline_match(self):
        """Word matcher must NOT fire if the word exists in baseline."""
        baseline = _make_response(text=self.FOOTER_HTML)
        fuzzed = _make_response(text=self.FUZZED_HTML)

        matcher = Matcher(
            type="word",
            part="body",
            words=["syntax error"],
            condition="or",
        )

        result = FuzzEngine._match_word(fuzzed, matcher, baseline)
        assert result is False, (
            "Word 'syntax error' exists in baseline footer — should NOT match"
        )

    def test_regex_matcher_rejects_baseline_match(self):
        """Regex matcher must NOT fire if the pattern appears in baseline."""
        baseline = _make_response(text=self.FOOTER_HTML)
        fuzzed = _make_response(text=self.FUZZED_HTML)

        matcher = Matcher(
            type="regex",
            part="body",
            regex=[r"syntax error"],
            condition="or",
        )

        result = FuzzEngine._match_regex(fuzzed, matcher, baseline)
        assert result is False, (
            "Regex 'syntax error' matches in baseline — should NOT match"
        )

    def test_fp_filter_rejects_baseline_evidence(self):
        """FP filter rejects findings whose evidence is in the baseline."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text=self.FOOTER_HTML)
        fuzzed = _make_response(text=self.FUZZED_HTML)

        finding = _make_finding(
            template_id="sqli-error",
            evidence="word match: syntax error",
        )

        result = fpf.should_keep(finding, baseline, fuzzed)
        assert result is False, (
            "Evidence 'syntax error' exists in baseline — should be rejected"
        )

    def test_genuine_sqli_error_still_detected(self):
        """A REAL SQLi error that does NOT appear in baseline IS detected."""
        baseline = _make_response(text="<html><body>Normal page</body></html>")
        fuzzed = _make_response(
            text="<html><body>Error: SQL syntax error near 'OR'</body></html>"
        )

        matcher = Matcher(
            type="regex",
            part="body",
            regex=[r"SQL syntax.*?error"],
            condition="or",
        )

        result = FuzzEngine._match_regex(fuzzed, matcher, baseline)
        assert result is True, (
            "Real SQLi error not in baseline — should match"
        )


# ═══════════════════════════════════════════════════════════════════
# Scenario 2: Slow server → NOT time-based SQLi
# ═══════════════════════════════════════════════════════════════════


class TestAlwaysSlowServer:
    """Server that always takes ~4 seconds to respond.

    A naturally slow server should NOT trigger time-based SQLi
    detection even when the response takes >3 seconds.
    """

    def test_timing_matcher_rejects_naturally_slow(self):
        """Timing matcher rejects when fuzzed time ≈ baseline time."""
        # Baseline averages 4000ms (server is naturally slow)
        baseline = _make_response(elapsed_ms=4000.0)
        # Fuzzed response also ~4200ms (not significantly different)
        fuzzed = _make_response(elapsed_ms=4200.0)

        matcher = Matcher(
            type="timing",
            part="response_time",
            threshold_ms=4500,
        )

        result = FuzzEngine._match_timing(fuzzed, baseline, matcher)
        assert result is False, (
            "4200ms fuzzed vs 4000ms baseline → threshold is "
            "max(4000+2500, 3500)=6500ms → 4200 < 6500 → should NOT match"
        )

    def test_timing_matcher_accepts_genuine_delay(self):
        """Timing matcher accepts when fuzzed time significantly exceeds baseline."""
        # Baseline averages 200ms
        baseline = _make_response(elapsed_ms=200.0)
        # SLEEP(5) causes 5200ms response
        fuzzed = _make_response(elapsed_ms=5200.0)

        matcher = Matcher(
            type="timing",
            part="response_time",
            threshold_ms=4500,
        )

        result = FuzzEngine._match_timing(fuzzed, baseline, matcher)
        assert result is True, (
            "5200ms fuzzed vs 200ms baseline → threshold is "
            "max(200+2500, 3500)=3500ms → 5200 > 3500 → should match"
        )

    def test_timing_fp_filter_rejects_small_delta(self):
        """FP filter rejects timing findings where fuzzed < 2x baseline."""
        fpf = FalsePositiveFilter()

        baseline = _make_response(elapsed_ms=4000.0)
        fuzzed = _make_response(elapsed_ms=5000.0)

        finding = _make_finding(
            template_id="sqli-time",
            evidence="elapsed=5000ms",
        )

        result = fpf.should_keep(finding, baseline, fuzzed)
        assert result is False, (
            "5000ms is only 1.25x of 4000ms baseline — must be 2x → reject"
        )

    def test_timing_fp_filter_accepts_large_delta(self):
        """FP filter accepts timing findings where fuzzed >= 2x baseline."""
        fpf = FalsePositiveFilter()

        baseline = _make_response(
            text="<html>Normal response body</html>",
            elapsed_ms=200.0,
        )
        fuzzed = _make_response(
            text="<html>Different response body with SQL output</html>",
            elapsed_ms=5200.0,
        )

        finding = _make_finding(
            template_id="sqli-time",
            evidence="elapsed=5200ms",
        )

        result = fpf.should_keep(finding, baseline, fuzzed)
        assert result is True, (
            "5200ms is 26x of 200ms baseline → should be kept"
        )

    def test_slow_server_edge_case_exactly_at_threshold(self):
        """Server with 1000ms baseline + SLEEP(3) = 4000ms total.

        Threshold = max(1000+2500, 3500) = 3500ms.
        4000 > 3500 → should match (genuine SQLi).
        """
        baseline = _make_response(elapsed_ms=1000.0)
        fuzzed = _make_response(elapsed_ms=4000.0)

        matcher = Matcher(type="timing", part="response_time", threshold_ms=4500)
        result = FuzzEngine._match_timing(fuzzed, baseline, matcher)
        assert result is True


# ═══════════════════════════════════════════════════════════════════
# Scenario 3: HTML-escaped input → NOT XSS
# ═══════════════════════════════════════════════════════════════════


class TestHTMLEscapedInput:
    """Server that properly HTML-escapes all user input.

    Injected XSS payloads should appear as &lt;script&gt; in the
    response — this is NOT vulnerable.
    """

    PAYLOAD = "<script>alert('sf_abc12345')</script>"
    NONCE = "sf_abc12345"

    ESCAPED_HTML = """
    <html>
    <body>
        <div>Search: &lt;script&gt;alert(&#x27;sf_abc12345&#x27;)&lt;/script&gt;</div>
    </body>
    </html>
    """

    UNESCAPED_HTML = """
    <html>
    <body>
        <div>Search: <script>alert('sf_abc12345')</script></div>
    </body>
    </html>
    """

    def test_fp_filter_rejects_escaped_xss(self):
        """FP filter rejects XSS when payload is HTML-entity-encoded."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text="<html><body>Search: </body></html>")
        fuzzed = _make_response(text=self.ESCAPED_HTML)

        finding = _make_finding(
            template_id="xss-reflected",
            payload=self.PAYLOAD,
            evidence="word match: <script>alert(",
        )

        result = fpf.should_keep(finding, baseline, fuzzed)
        assert result is False, (
            "Payload is HTML-escaped in response — should be rejected"
        )

    def test_fp_filter_keeps_unescaped_xss(self):
        """FP filter keeps XSS when payload appears unescaped in response."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text="<html><body>Search: </body></html>")
        fuzzed = _make_response(text=self.UNESCAPED_HTML)

        finding = _make_finding(
            template_id="xss-reflected",
            payload=self.PAYLOAD,
            evidence="word match: <script>alert(",
        )

        result = fpf.should_keep(finding, baseline, fuzzed)
        assert result is True, (
            "Payload appears unescaped in response — should be kept"
        )

    def test_verify_xss_in_script_tag(self):
        """verify_xss_unescaped confirms nonce inside a real <script> tag."""
        result = verify_xss_unescaped(self.UNESCAPED_HTML, self.NONCE)
        assert result is True, (
            "Nonce appears inside real <script> tag — should be confirmed"
        )

    def test_verify_xss_not_in_script_tag(self):
        """verify_xss_unescaped rejects nonce that's only in text content."""
        safe_html = """
        <html><body>
            <p>Your search: sf_abc12345 returned no results</p>
        </body></html>
        """
        result = verify_xss_unescaped(safe_html, self.NONCE)
        assert result is False, (
            "Nonce only appears in <p> text, not in <script> — reject"
        )

    def test_verify_xss_escaped_entities(self):
        """verify_xss_unescaped rejects entity-encoded script tags."""
        result = verify_xss_unescaped(self.ESCAPED_HTML, self.NONCE)
        assert result is False, (
            "Nonce only appears in entity-encoded context — reject"
        )

    def test_verify_xss_in_event_handler(self):
        """verify_xss_unescaped detects nonce in on* event attributes."""
        html = '<html><body><img src=x onerror="alert(\'sf_abc12345\')"></body></html>'
        result = verify_xss_unescaped(html, self.NONCE)
        assert result is True, (
            "Nonce in onerror event handler — should be confirmed as XSS"
        )

    def test_verify_xss_in_html_comment(self):
        """verify_xss_unescaped rejects nonce inside HTML comments."""
        html = """
        <html><body>
            <!-- <script>alert('sf_abc12345')</script> -->
            <p>Normal content</p>
        </body></html>
        """
        result = verify_xss_unescaped(html, self.NONCE)
        assert result is False, (
            "Nonce only in HTML comment — not exploitable — reject"
        )

    def test_word_matcher_rejects_escaped_payload_in_baseline(self):
        """Word matcher should NOT fire if escaped payload is 'reflected'."""
        baseline = _make_response(text="<html><body>Normal</body></html>")
        # The word we search for literally: "<script>alert("
        # But in the response it only appears escaped: "&lt;script&gt;alert("
        fuzzed = _make_response(text=self.ESCAPED_HTML)

        matcher = Matcher(
            type="word",
            part="body",
            words=["<script>alert("],
        )

        # The word does NOT appear literally (it's entity-encoded) → no match
        result = FuzzEngine._match_word(fuzzed, matcher, baseline)
        assert result is False, (
            "Escaped payload should not match literal word search"
        )


# ═══════════════════════════════════════════════════════════════════
# Deduplicator Tests
# ═══════════════════════════════════════════════════════════════════


class TestDeduplicator:
    """Test that the deduplicator correctly removes redundant findings."""

    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_single_finding(self):
        f = _make_finding()
        result = deduplicate([f])
        assert len(result) == 1

    def test_same_vuln_same_param_keeps_highest_confidence(self):
        """Duplicate (template_id, url, parameter) → keep highest confidence."""
        f1 = _make_finding(
            template_id="sqli-error", parameter="query:id", confidence=0.6,
        )
        f2 = _make_finding(
            template_id="sqli-error", parameter="query:id", confidence=0.9,
        )
        result = deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_same_vuln_different_param_kept(self):
        """Same template on different parameters → both kept."""
        f1 = _make_finding(template_id="sqli-error", parameter="query:id")
        f2 = _make_finding(template_id="sqli-error", parameter="query:name")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_different_templates_same_param_kept(self):
        """Different templates on same parameter → both kept."""
        f1 = _make_finding(template_id="sqli-error", parameter="query:id")
        f2 = _make_finding(template_id="xss-reflected", parameter="query:id")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_passive_findings_deduplicated_globally(self):
        """Header findings are deduplicated to one-per-template across all pages."""
        f1 = _make_finding(
            template_id="security-headers",
            url="http://test.local/page1",
            parameter="n/a",
            payload="(passive check)",
            confidence=0.6,
        )
        f2 = _make_finding(
            template_id="security-headers",
            url="http://test.local/page2",
            parameter="n/a",
            payload="(passive check)",
            confidence=0.8,
        )
        f3 = _make_finding(
            template_id="security-headers",
            url="http://test.local/page3",
            parameter="n/a",
            payload="(passive check)",
            confidence=0.7,
        )
        result = deduplicate([f1, f2, f3])
        assert len(result) == 1, (
            "Three passive findings for same template → collapsed to 1"
        )
        assert result[0].confidence == 0.8  # Highest confidence kept

    def test_mix_of_active_and_passive(self):
        """Mixed active + passive findings deduplicate independently."""
        active1 = _make_finding(template_id="sqli-error", parameter="query:id")
        active2 = _make_finding(template_id="sqli-error", parameter="query:id")
        passive1 = _make_finding(
            template_id="security-headers", parameter="n/a",
            payload="(passive check)",
        )
        passive2 = _make_finding(
            template_id="security-headers", parameter="n/a",
            payload="(passive check)", url="http://other.local/page2",
        )
        result = deduplicate([active1, active2, passive1, passive2])
        # 2 active same key → 1, 2 passive same template → 1
        assert len(result) == 2


# ═══════════════════════════════════════════════════════════════════
# FP Filter — Individual Rule Tests
# ═══════════════════════════════════════════════════════════════════


class TestFPFilterRules:
    """Test each FP filter rule in isolation."""

    def test_response_differential_identical_body_rejects(self):
        """Identical status + identical body → reject."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text="exactly the same", status_code=200)
        fuzzed = _make_response(text="exactly the same", status_code=200)

        finding = _make_finding(template_id="sqli-error", evidence="status=200")
        result = fpf.should_keep(finding, baseline, fuzzed)
        # Status-only evidence won't trigger baseline_exclusion but
        # the differential rule will reject since bodies are identical
        assert result is False

    def test_response_differential_different_status_keeps(self):
        """Different status code → keep (something changed)."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text="OK", status_code=200)
        fuzzed = _make_response(text="OK", status_code=500)

        finding = _make_finding(evidence="status=500")
        result = fpf._rule_response_differential(baseline, fuzzed)
        assert result is True

    def test_response_differential_different_body_keeps(self):
        """Same status but very different body → keep."""
        fpf = FalsePositiveFilter()
        baseline = _make_response(text="Normal page content", status_code=200)
        fuzzed = _make_response(
            text="Error: SQL syntax error near '" + "x" * 100,
            status_code=200,
        )

        result = fpf._rule_response_differential(baseline, fuzzed)
        assert result is True

    def test_xss_rule_not_applied_to_sqli(self):
        """XSS escape rule should not affect SQLi templates."""
        fpf = FalsePositiveFilter()
        finding = _make_finding(template_id="sqli-error", payload="' OR 1=1")
        fuzzed = _make_response(text="Error")

        result = fpf._rule_xss_unescaped(finding, fuzzed)
        assert result is True, "Non-XSS template should always pass XSS rule"

    def test_timing_rule_not_applied_to_xss(self):
        """Timing rule should not affect XSS templates."""
        fpf = FalsePositiveFilter()
        finding = _make_finding(template_id="xss-reflected")
        baseline = _make_response(elapsed_ms=100)
        fuzzed = _make_response(elapsed_ms=100)

        result = fpf._rule_timing_significance(finding, baseline, fuzzed)
        assert result is True, "Non-timing template should always pass timing rule"


# ═══════════════════════════════════════════════════════════════════
# Baseline-Aware Matcher Tests
# ═══════════════════════════════════════════════════════════════════


class TestBaselineAwareMatchers:
    """Test that word and regex matchers exclude baseline content."""

    def test_word_new_match_detected(self):
        """Word that appears in fuzzed but NOT baseline → match."""
        baseline = _make_response(text="Normal page")
        fuzzed = _make_response(text="Normal page <script>alert(1)</script>")

        matcher = Matcher(type="word", part="body", words=["<script>alert("])
        result = FuzzEngine._match_word(fuzzed, matcher, baseline)
        assert result is True

    def test_word_baseline_match_excluded(self):
        """Word that appears in BOTH baseline and fuzzed → no match."""
        baseline = _make_response(text="Page with <script>alert( in it")
        fuzzed = _make_response(text="Page with <script>alert( in it still")

        matcher = Matcher(type="word", part="body", words=["<script>alert("])
        result = FuzzEngine._match_word(fuzzed, matcher, baseline)
        assert result is False

    def test_regex_new_match_detected(self):
        """Regex that matches in fuzzed but NOT baseline → match."""
        baseline = _make_response(text="Normal page")
        fuzzed = _make_response(text="Warning: mysql_fetch_array()")

        matcher = Matcher(type="regex", part="body", regex=[r"Warning.*?mysql_"])
        result = FuzzEngine._match_regex(fuzzed, matcher, baseline)
        assert result is True

    def test_regex_baseline_match_excluded(self):
        """Regex that matches in BOTH baseline and fuzzed → no match."""
        common_text = "Warning: mysql_fetch_array() - this is documentation"
        baseline = _make_response(text=common_text)
        fuzzed = _make_response(text=common_text)

        matcher = Matcher(type="regex", part="body", regex=[r"Warning.*?mysql_"])
        result = FuzzEngine._match_regex(fuzzed, matcher, baseline)
        assert result is False

    def test_word_without_baseline_works(self):
        """Word matcher still works when baseline is None."""
        fuzzed = _make_response(text="Has <script>alert(1)</script>")

        matcher = Matcher(type="word", part="body", words=["<script>alert("])
        result = FuzzEngine._match_word(fuzzed, matcher, None)
        assert result is True

    def test_regex_without_baseline_works(self):
        """Regex matcher still works when baseline is None."""
        fuzzed = _make_response(text="ORA-12345 error")

        matcher = Matcher(type="regex", part="body", regex=[r"ORA-\d{5}"])
        result = FuzzEngine._match_regex(fuzzed, matcher, None)
        assert result is True

    def test_and_condition_all_must_be_new(self):
        """AND condition: all words must be new (not in baseline)."""
        baseline = _make_response(text="Has word1 in it")
        fuzzed = _make_response(text="Has word1 and word2 in it")

        matcher = Matcher(
            type="word", part="body",
            words=["word1", "word2"], condition="and",
        )
        # word1 is in baseline, so it fails AND
        result = FuzzEngine._match_word(fuzzed, matcher, baseline)
        assert result is False
