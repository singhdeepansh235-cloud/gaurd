"""Data models for Sentinal-Fuzz scan pipeline.

All core data structures used across the crawler, fuzzer, analyzer,
and reporter modules. Built on dataclasses for simplicity and
stdlib compatibility.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SeverityLevel(Enum):
    """Vulnerability severity classification aligned with CVSS v3.1 ranges.

    Attributes:
        CRITICAL: CVSS 9.0-10.0 -- RCE, auth bypass, mass data exfiltration.
        HIGH:     CVSS 7.0-8.9  -- SQLi, stored XSS, SSRF, privilege escalation.
        MEDIUM:   CVSS 4.0-6.9  -- Reflected XSS, CSRF, info disclosure.
        LOW:      CVSS 0.1-3.9  -- Missing headers, verbose errors, cookie flags.
        INFO:     CVSS 0.0      -- Fingerprinting, banners, open ports.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        """Rich-compatible color for terminal display."""
        return {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "dim",
        }[self]

    @property
    def emoji(self) -> str:
        """Emoji icon for terminal display."""
        return {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🔵",
            SeverityLevel.INFO: "⚪",
        }[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        order = [
            SeverityLevel.INFO,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        ]
        return order.index(self) < order.index(other)


@dataclass
class Endpoint:
    """A discovered web endpoint with its input vectors.

    Represents a single URL + method combination along with all the
    input points (query params, form fields, headers, cookies) that
    the fuzzer should test.

    Attributes:
        url:     The full URL of the endpoint.
        method:  HTTP method (GET, POST, PUT, DELETE, etc.).
        params:  Query parameters as name→value mappings.
        headers: Relevant request headers captured during crawling.
        forms:   Form field definitions (name, type, default value).
        cookies: Cookies associated with this endpoint.
        source:  How this endpoint was discovered (crawl, sitemap, api-spec).
    """

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    forms: list[dict[str, str]] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    source: str = "crawl"
    is_api: bool = False

    @property
    def injectable_params(self) -> list[str]:
        """Return a list of parameter names that can be fuzz targets."""
        param_names = list(self.params.keys())
        form_names = [f.get("name", "") for f in self.forms if f.get("name")]
        return param_names + form_names

    def __hash__(self) -> int:
        return hash((self.url, self.method, frozenset(self.params.items())))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Endpoint):
            return NotImplemented
        return (
            self.url == other.url
            and self.method == other.method
            and self.params == other.params
        )


@dataclass
class HttpExchange:
    """A captured HTTP request/response pair used as evidence.

    Attributes:
        method:           HTTP method used.
        url:              Full request URL.
        request_headers:  Headers sent in the request.
        request_body:     Request body (for POST/PUT).
        status_code:      HTTP response status code.
        response_headers: Headers returned in the response.
        response_body:    Response body content.
        elapsed_ms:       Round-trip time in milliseconds.
    """

    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0.0


@dataclass
class Finding:
    """A confirmed or suspected vulnerability finding.

    Produced by the fuzzer after a payload triggers a response that
    matches a detection rule. Each finding includes full evidence
    (request/response) and remediation guidance.

    Attributes:
        id:            Unique identifier (UUID) for this finding.
        title:         Human-readable vulnerability title.
        severity:      Severity classification.
        url:           The URL where the vulnerability was found.
        parameter:     The specific parameter that was vulnerable.
        payload:       The payload that triggered the finding.
        evidence:      Description of what confirmed the vulnerability.
        request:       The HTTP exchange that demonstrated the issue.
        response:      Raw response body excerpt showing the vulnerability.
        cwe:           CWE identifier (e.g., "CWE-89").
        owasp:         OWASP Top 10 category (e.g., "A03:2021-Injection").
        remediation:   Suggested fix for the vulnerability.
        confidence:    Confidence score (0.0-1.0).
        template_id:   ID of the fuzzing template that produced this finding.
        timestamp:     When the finding was discovered.
    """

    title: str
    severity: SeverityLevel
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: HttpExchange | None = None
    response: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    confidence: float = 1.0
    template_id: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a JSON-compatible dict."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "template_id": self.template_id,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanStats:
    """Aggregate statistics for a completed scan.

    Attributes:
        total_requests:  Total HTTP requests sent during the scan.
        urls_crawled:    Number of unique URLs visited by the crawler.
        endpoints_found: Number of unique endpoints discovered.
        templates_run:   Number of fuzzing templates executed.
        findings_by_severity: Count of findings grouped by severity level.
        requests_per_second:  Average throughput during fuzzing.
    """

    total_requests: int = 0
    urls_crawled: int = 0
    endpoints_found: int = 0
    templates_run: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=lambda: {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    })
    requests_per_second: float = 0.0


@dataclass
class ScanResult:
    """Complete result of a DAST scan.

    This is the top-level data structure returned by Scanner.run().
    It contains everything needed to generate reports in any format.

    Attributes:
        target:          The target URL that was scanned.
        start_time:      When the scan started.
        end_time:        When the scan completed (None if still running).
        endpoints:       All discovered endpoints.
        findings:        All vulnerability findings.
        stats:           Aggregate scan statistics.
        scan_id:         Unique identifier for this scan run.
        scan_profile:    Which scan profile was used (quick/standard/thorough).
        scanner_version: Version of Sentinal-Fuzz that produced this result.
    """

    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    scan_profile: str = "standard"
    scanner_version: str = "0.1.0"

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        if self.end_time is None:
            return (datetime.now() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()

    @property
    def findings_by_severity(self) -> dict[SeverityLevel, list[Finding]]:
        """Group findings by their severity level."""
        grouped: dict[SeverityLevel, list[Finding]] = {level: [] for level in SeverityLevel}
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped

    @property
    def critical_count(self) -> int:
        """Number of critical findings."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of high-severity findings."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the scan result to a JSON-compatible dict."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scanner_version": self.scanner_version,
            "scan_profile": self.scan_profile,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "endpoints_found": len(self.endpoints),
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
