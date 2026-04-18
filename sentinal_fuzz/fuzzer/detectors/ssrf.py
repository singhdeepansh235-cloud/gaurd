"""SSRF (Server-Side Request Forgery) detector for Sentinal-Fuzz.

Generates canary callback URLs, injects them into URL/redirect parameters,
and checks responses for signs of internal resource access (internal IPs,
AWS metadata content, DNS resolution markers).

Usage::

    detector = SSRFDetector()
    findings = detector.analyze(endpoint, response, injection_point, payload)
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.utils.http import Response

log = get_logger("detector.ssrf")

# ── Internal IP regex patterns ─────────────────────────────────────
_INTERNAL_IP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[^\d])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:[^\d]|$)"),
    re.compile(r"(?:^|[^\d])192\.168\.\d{1,3}\.\d{1,3}(?:[^\d]|$)"),
    re.compile(
        r"(?:^|[^\d])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?:[^\d]|$)",
    ),
    re.compile(r"(?:^|[^\d])127\.0\.0\.\d{1,3}(?:[^\d]|$)"),
    re.compile(r"(?:^|[^\d])169\.254\.169\.254(?:[^\d]|$)"),
]

# AWS / cloud metadata indicators in response body
_METADATA_KEYWORDS: list[str] = [
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "AccessKeyId",
    "SecretAccessKey",
    "computeMetadata",
    "droplet_id",
]

# Parameter names that are likely URL / redirect targets
SSRF_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "uri", "link", "href", "src", "source",
    "redirect", "redirect_url", "redirect_uri",
    "next", "return", "returnUrl", "return_url",
    "callback", "cb", "dest", "destination",
    "target", "fetch", "load", "proxy",
    "path", "file", "page", "feed",
})


class SSRFDetector:
    """Detect Server-Side Request Forgery vulnerabilities.

    The detector works in two modes:

    1. **Canary injection** -- generates a unique canary domain
       (``ssrf-{uuid}.sentinal.local``) as the payload. If the
       server resolves or fetches it, we have SSRF.
    2. **Response analysis** -- scans every response for signs
       that internal resources were accessed (internal IPs, cloud
       metadata content).
    """

    def __init__(self) -> None:
        self._canary_id: str = uuid.uuid4().hex[:12]

    @property
    def canary_domain(self) -> str:
        """Return the unique canary domain for this scan."""
        return f"ssrf-{self._canary_id}.sentinal.local"

    @property
    def canary_url(self) -> str:
        """Return the full canary URL for payload injection."""
        return f"http://{self.canary_domain}/callback"

    def generate_payloads(self) -> list[str]:
        """Return SSRF payloads including the canary URL."""
        canary = self.canary_url
        return [
            canary,
            f"https://{self.canary_domain}/callback",
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://[::1]:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        ]

    @staticmethod
    def is_ssrf_param(param_name: str) -> bool:
        """Check if a parameter name suggests a URL/redirect target."""
        return param_name.lower() in SSRF_PARAM_NAMES

    def analyze_response(self, response: Response) -> list[str]:
        """Scan a response for SSRF indicators.

        Returns a list of evidence strings for each indicator found.
        """
        evidence: list[str] = []
        body = response.text

        # Check for internal IP addresses in response body
        for pattern in _INTERNAL_IP_PATTERNS:
            match = pattern.search(body)
            if match:
                evidence.append(f"Internal IP found: {match.group().strip()}")

        # Check for cloud metadata content
        for keyword in _METADATA_KEYWORDS:
            if keyword.lower() in body.lower():
                evidence.append(f"Metadata indicator: {keyword}")

        # Check if canary domain appears in response (DNS resolution proof)
        if self.canary_domain in body:
            evidence.append(f"Canary domain resolved: {self.canary_domain}")

        return evidence

    def create_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        evidence: list[str],
    ) -> Finding:
        """Build an SSRF Finding from detection evidence."""
        return Finding(
            title="Server-Side Request Forgery (SSRF)",
            severity=SeverityLevel.HIGH,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=" | ".join(evidence)[:200],
            cwe="CWE-918",
            owasp="A10:2021-SSRF",
            remediation=(
                "Validate and whitelist destination URLs on the server side. "
                "Block requests to private/internal IP ranges and cloud "
                "metadata endpoints (169.254.169.254). Use DNS resolution "
                "checks to prevent DNS-rebinding attacks."
            ),
            confidence=0.8 if len(evidence) >= 2 else 0.6,
            template_id="ssrf-detector",
        )
