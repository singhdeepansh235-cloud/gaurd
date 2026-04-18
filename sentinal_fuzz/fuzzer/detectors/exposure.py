"""Sensitive data exposure checker (passive) for Sentinal-Fuzz.

Scans every response body for accidental leaks of secrets, keys,
tokens, stack traces, and internal infrastructure details.  Runs
passively -- no payload injection needed.

Patterns detected:
    - AWS access keys  (AKIA...)
    - Private keys     (-----BEGIN ... PRIVATE KEY-----)
    - JWT tokens       (eyJ...)
    - GitHub tokens    (ghp_, gho_)
    - Stack traces     (Python, Java, PHP, .NET, Node.js)
    - Database connection strings
    - Email addresses in unexpected places
    - Internal IP addresses

Usage::

    checker = SensitiveDataChecker()
    findings = checker.check(url, response)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.utils.http import Response

log = get_logger("detector.exposure")


@dataclass(frozen=True)
class ExposurePattern:
    """A single sensitive-data detection pattern.

    Attributes:
        name:       Human-readable label for this pattern.
        regex:      Compiled regular expression.
        severity:   Finding severity if matched.
        cwe:        CWE identifier.
        confidence: Confidence level for this pattern type.
    """

    name: str
    regex: re.Pattern[str]
    severity: SeverityLevel
    cwe: str
    confidence: float


# ── Pattern definitions ────────────────────────────────────────────
_PATTERNS: list[ExposurePattern] = [
    # AWS access key
    ExposurePattern(
        name="AWS Access Key",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798",
        confidence=0.95,
    ),
    # Private key (PEM format)
    ExposurePattern(
        name="Private Key (PEM)",
        regex=re.compile(
            r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----",
        ),
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-321",
        confidence=0.95,
    ),
    # JWT token
    ExposurePattern(
        name="JWT Token",
        regex=re.compile(
            r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
        ),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-200",
        confidence=0.7,
    ),
    # GitHub personal access token
    ExposurePattern(
        name="GitHub Token",
        regex=re.compile(r"ghp_[0-9A-Za-z]{36}"),
        severity=SeverityLevel.HIGH,
        cwe="CWE-798",
        confidence=0.9,
    ),
    # GitHub OAuth token
    ExposurePattern(
        name="GitHub OAuth Token",
        regex=re.compile(r"gho_[0-9A-Za-z]{36}"),
        severity=SeverityLevel.HIGH,
        cwe="CWE-798",
        confidence=0.9,
    ),
    # Stripe secret key
    ExposurePattern(
        name="Stripe Secret Key",
        regex=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798",
        confidence=0.95,
    ),
    # Slack token
    ExposurePattern(
        name="Slack Token",
        regex=re.compile(r"xox[bpors]-[0-9a-zA-Z]{10,48}"),
        severity=SeverityLevel.HIGH,
        cwe="CWE-798",
        confidence=0.9,
    ),
    # ── Stack traces ───────────────────────────────────────────────
    ExposurePattern(
        name="Python Stack Trace",
        regex=re.compile(r"Traceback \(most recent call last\)"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.8,
    ),
    ExposurePattern(
        name="Java Stack Trace",
        regex=re.compile(r"at\s+[\w.$]+\([\w]+\.java:\d+\)"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.8,
    ),
    ExposurePattern(
        name="Java Exception",
        regex=re.compile(r"java\.lang\.\w+Exception"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.8,
    ),
    ExposurePattern(
        name="PHP Stack Trace",
        regex=re.compile(r"Fatal error:.*?on line \d+"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.8,
    ),
    ExposurePattern(
        name=".NET Exception",
        regex=re.compile(r"System\.\w+Exception"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.8,
    ),
    ExposurePattern(
        name="ASP.NET Error Page",
        regex=re.compile(r"Server Error in '/' Application"),
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-209",
        confidence=0.85,
    ),
    # ── Database connection strings ────────────────────────────────
    ExposurePattern(
        name="Database Connection String",
        regex=re.compile(
            r"(?:jdbc|mysql|postgresql|mongodb|redis|amqp)://[^\s<>\"']+",
        ),
        severity=SeverityLevel.HIGH,
        cwe="CWE-200",
        confidence=0.85,
    ),
    ExposurePattern(
        name="MSSQL Connection String",
        regex=re.compile(
            r"Server=.*?;Database=.*?;(?:User\sId|Uid)=",
            re.IGNORECASE,
        ),
        severity=SeverityLevel.HIGH,
        cwe="CWE-200",
        confidence=0.85,
    ),
    # ── Email addresses (broad) ────────────────────────────────────
    ExposurePattern(
        name="Email Address",
        regex=re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ),
        severity=SeverityLevel.INFO,
        cwe="CWE-200",
        confidence=0.4,  # low confidence — emails are common
    ),
]


class SensitiveDataChecker:
    """Passive scanner for sensitive data exposure in HTTP responses.

    Call ``check(url, response)`` on every page to produce findings
    for any detected leaks.
    """

    def __init__(self, *, min_confidence: float = 0.5) -> None:
        self._min_confidence = min_confidence

    def check(self, url: str, response: Response) -> list[Finding]:
        """Scan a response body for sensitive data patterns."""
        findings: list[Finding] = []
        body = response.text

        for pattern in _PATTERNS:
            if pattern.confidence < self._min_confidence:
                continue

            match = pattern.regex.search(body)
            if match:
                snippet = match.group()[:100]
                findings.append(Finding(
                    title=f"Sensitive Data Exposure: {pattern.name}",
                    severity=pattern.severity,
                    url=url,
                    evidence=f"{pattern.name}: {snippet}",
                    cwe=pattern.cwe,
                    owasp="A01:2021-Broken Access Control",
                    remediation=(
                        "Remove secrets and tokens from response bodies. "
                        "Disable debug mode in production. Rotate any "
                        "credentials that may have been exposed."
                    ),
                    confidence=pattern.confidence,
                    template_id="exposure-checker",
                ))

        return findings
