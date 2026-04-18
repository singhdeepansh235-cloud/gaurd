"""Finding aggregator for Sentinal-Fuzz.

Produces an ``AnalysisReport`` from a list of enriched findings,
containing severity distributions, OWASP category breakdowns,
risk scoring, and scan coverage metrics.

Usage::

    from sentinal_fuzz.analyzer.aggregator import aggregate, AnalysisReport

    report = aggregate(enriched_findings, total_endpoints=42)
    print(report.risk_score, report.by_severity)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from sentinal_fuzz.analyzer.classifier import EnrichedFinding
from sentinal_fuzz.core.models import SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("aggregator")


# Severity weights for risk score calculation
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 10.0,
    "low": 3.0,
    "info": 0.5,
}


@dataclass
class AnalysisReport:
    """Aggregated analysis report produced from enriched findings.

    Attributes:
        total_findings:          Total number of findings.
        by_severity:             Count of findings per severity level.
        by_owasp:                Count of findings per OWASP Top 10 category.
        unique_endpoints_affected: Number of unique endpoint URLs with findings.
        highest_severity:        The highest severity level found.
        risk_score:              Weighted risk score (0\u2013100).
        scan_coverage:           Percentage of total endpoints that were tested.
        by_cwe:                  Count of findings per CWE ID.
        by_exploit_difficulty:   Count of findings per exploit difficulty.
        avg_cvss:                Average CVSS score across all findings.
        avg_confidence:          Average confidence score across all findings.
    """

    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    })
    by_owasp: dict[str, int] = field(default_factory=dict)
    unique_endpoints_affected: int = 0
    highest_severity: str = "Info"
    risk_score: float = 0.0
    scan_coverage: float = 0.0
    by_cwe: dict[str, int] = field(default_factory=dict)
    by_exploit_difficulty: dict[str, int] = field(default_factory=dict)
    avg_cvss: float = 0.0
    avg_confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-compatible dict."""
        return {
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_owasp": self.by_owasp,
            "by_cwe": self.by_cwe,
            "by_exploit_difficulty": self.by_exploit_difficulty,
            "unique_endpoints_affected": self.unique_endpoints_affected,
            "highest_severity": self.highest_severity,
            "risk_score": round(self.risk_score, 1),
            "scan_coverage": round(self.scan_coverage, 1),
            "avg_cvss": round(self.avg_cvss, 1),
            "avg_confidence": round(self.avg_confidence, 2),
        }


def aggregate(
    findings: list[EnrichedFinding],
    total_endpoints: int = 0,
) -> AnalysisReport:
    """Aggregate enriched findings into an AnalysisReport.

    Args:
        findings:         List of enriched findings to aggregate.
        total_endpoints:  Total number of endpoints discovered during
                          the scan (used to compute scan coverage).

    Returns:
        An ``AnalysisReport`` with all metrics computed.
    """
    if not findings:
        return AnalysisReport(
            scan_coverage=0.0 if total_endpoints == 0 else 0.0,
        )

    report = AnalysisReport()
    report.total_findings = len(findings)

    # ── Severity distribution ──────────────────────────────────
    severity_order = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
    ]
    severity_display = {
        SeverityLevel.CRITICAL: "Critical",
        SeverityLevel.HIGH: "High",
        SeverityLevel.MEDIUM: "Medium",
        SeverityLevel.LOW: "Low",
        SeverityLevel.INFO: "Info",
    }

    for finding in findings:
        display = severity_display.get(finding.severity, "Info")
        report.by_severity[display] = report.by_severity.get(display, 0) + 1

    # ── Highest severity ───────────────────────────────────────
    for level in severity_order:
        display = severity_display[level]
        if report.by_severity.get(display, 0) > 0:
            report.highest_severity = display
            break

    # ── OWASP category distribution ────────────────────────────
    for finding in findings:
        cat = finding.owasp_category or finding.owasp or "Uncategorized"
        report.by_owasp[cat] = report.by_owasp.get(cat, 0) + 1

    # ── CWE distribution ───────────────────────────────────────
    for finding in findings:
        cwe = finding.cwe_id or finding.cwe or "Unknown"
        if cwe:
            report.by_cwe[cwe] = report.by_cwe.get(cwe, 0) + 1

    # ── Exploit difficulty distribution ────────────────────────
    for finding in findings:
        diff = finding.exploit_difficulty or "unknown"
        report.by_exploit_difficulty[diff] = (
            report.by_exploit_difficulty.get(diff, 0) + 1
        )

    # ── Unique endpoints affected ──────────────────────────────
    affected_urls: set[str] = set()
    for finding in findings:
        # Normalize URL to just scheme + host + path (ignore query)
        parsed = urlparse(finding.url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        affected_urls.add(normalized)
    report.unique_endpoints_affected = len(affected_urls)

    # ── Risk score (0–100) ─────────────────────────────────────
    raw_score = 0.0
    for finding in findings:
        weight = _SEVERITY_WEIGHTS.get(finding.severity.value, 0.5)
        raw_score += weight
    # Cap at 100, scale logarithmically for large finding counts
    report.risk_score = min(100.0, raw_score)

    # ── Scan coverage ──────────────────────────────────────────
    if total_endpoints > 0:
        report.scan_coverage = (
            report.unique_endpoints_affected / total_endpoints * 100.0
        )
    else:
        report.scan_coverage = 0.0

    # ── Average CVSS ───────────────────────────────────────────
    cvss_scores = [f.cvss_score for f in findings if f.cvss_score > 0]
    if cvss_scores:
        report.avg_cvss = sum(cvss_scores) / len(cvss_scores)

    # ── Average confidence ─────────────────────────────────────
    confidences = [f.confidence for f in findings]
    if confidences:
        report.avg_confidence = sum(confidences) / len(confidences)

    log.info(
        "Analysis report: %d findings, risk score %.1f, "
        "highest=%s, %d unique endpoints",
        report.total_findings, report.risk_score,
        report.highest_severity, report.unique_endpoints_affected,
    )

    return report
