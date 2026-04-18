"""JSON report generator for Sentinal-Fuzz.

Produces a machine-readable JSON file with the complete scan result.
The output is designed to be re-loadable so it can regenerate other
report formats (HTML, SARIF, terminal) without re-scanning.

Usage::

    from sentinal_fuzz.reporter.json_reporter import JsonReporter

    reporter = JsonReporter(output_dir="reports")
    filepath = reporter.generate(scan_result)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from sentinal_fuzz.core.models import (
    Endpoint,
    Finding,
    HttpExchange,
    ScanResult,
    ScanStats,
    SeverityLevel,
)
from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("json_reporter")


@dataclass
class JsonReporter(BaseReporter):
    """Generate a comprehensive JSON report from scan results.

    The JSON structure includes:
    - ``metadata``: Scan ID, target, scanner version, timestamps.
    - ``summary``: Severity counts, risk score, total findings.
    - ``endpoints``: All discovered endpoints with their input vectors.
    - ``findings``: Full enriched findings with request/response evidence.
    - ``stats``: Scan performance statistics.
    """

    @property
    def file_extension(self) -> str:
        return ".json"

    @property
    def format_name(self) -> str:
        return "JSON"

    def generate(self, result: ScanResult) -> str:
        """Generate a JSON report and write it to disk.

        Args:
            result: The complete scan result.

        Returns:
            Absolute file path of the generated JSON report.
        """
        report_data = self.build_report_dict(result)
        content = json.dumps(report_data, indent=2, ensure_ascii=False, default=str)
        filename = self._build_filename(result)
        filepath = self._write_file(filename, content)
        log.info("JSON report generated: %s", filepath)
        return filepath

    @staticmethod
    def build_report_dict(result: ScanResult) -> dict[str, Any]:
        """Build the complete report dictionary.

        This is the canonical structure that other reporters can consume.

        Args:
            result: The scan result to serialize.

        Returns:
            A JSON-serializable dictionary.
        """
        severity_counts = {level.value: 0 for level in SeverityLevel}
        for finding in result.findings:
            severity_counts[finding.severity.value] += 1

        risk_score = _compute_risk_score(result)

        return {
            "schema_version": "1.0.0",
            "generator": "sentinal-fuzz",
            "metadata": {
                "scan_id": result.scan_id,
                "target": result.target,
                "scanner_version": result.scanner_version,
                "scan_profile": result.scan_profile,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": result.duration_seconds,
            },
            "summary": {
                "total_findings": len(result.findings),
                "severity_counts": severity_counts,
                "risk_score": risk_score,
                "endpoints_discovered": len(result.endpoints),
                "most_critical": _most_critical_finding(result),
            },
            "endpoints": [_serialize_endpoint(ep) for ep in result.endpoints],
            "findings": [_serialize_finding(f) for f in result.findings],
            "stats": {
                "total_requests": result.stats.total_requests,
                "urls_crawled": result.stats.urls_crawled,
                "endpoints_found": result.stats.endpoints_found,
                "templates_run": result.stats.templates_run,
                "findings_by_severity": result.stats.findings_by_severity,
                "requests_per_second": result.stats.requests_per_second,
            },
        }


# ── Serialization helpers ──────────────────────────────────────────


def _serialize_endpoint(endpoint: Endpoint) -> dict[str, Any]:
    """Serialize an Endpoint to a JSON-compatible dict."""
    return {
        "url": endpoint.url,
        "method": endpoint.method,
        "params": endpoint.params,
        "forms": endpoint.forms,
        "headers": {k: v for k, v in endpoint.headers.items()},
        "cookies": {k: v for k, v in endpoint.cookies.items()},
        "source": endpoint.source,
        "is_api": endpoint.is_api,
        "injectable_params": endpoint.injectable_params,
    }


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Serialize a Finding with full enrichment."""
    data = finding.to_dict()
    # Add request/response evidence if available
    if finding.request:
        data["request_evidence"] = {
            "method": finding.request.method,
            "url": finding.request.url,
            "request_headers": finding.request.request_headers,
            "request_body": finding.request.request_body,
            "status_code": finding.request.status_code,
            "response_headers": finding.request.response_headers,
            "response_body": finding.request.response_body[:2000],
            "elapsed_ms": finding.request.elapsed_ms,
        }
    else:
        data["request_evidence"] = None
    data["response_excerpt"] = finding.response[:2000] if finding.response else ""
    return data


def _most_critical_finding(result: ScanResult) -> dict[str, str] | None:
    """Return the most critical finding as a summary dict."""
    if not result.findings:
        return None
    # Sort by severity (highest first)
    severity_order = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
    ]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.severity),
    )
    top = sorted_findings[0]
    return {
        "title": top.title,
        "severity": top.severity.value,
        "url": top.url,
        "parameter": top.parameter,
    }


def _compute_risk_score(result: ScanResult) -> int:
    """Compute an overall risk score from 0-100.

    Scoring:
    - Critical: +25 each (max 100)
    - High:     +15 each (max 60)
    - Medium:   +5 each  (max 25)
    - Low:      +2 each  (max 10)
    - Info:     +0
    """
    score = 0
    for f in result.findings:
        if f.severity == SeverityLevel.CRITICAL:
            score += 25
        elif f.severity == SeverityLevel.HIGH:
            score += 15
        elif f.severity == SeverityLevel.MEDIUM:
            score += 5
        elif f.severity == SeverityLevel.LOW:
            score += 2
    return min(score, 100)
