"""Security header checker (passive) for Sentinal-Fuzz.

Runs on every fetched page -- no payloads needed.  Checks for
missing or misconfigured HTTP security headers and creates a
``Finding`` for each issue.

Checks performed:
    - Missing Content-Security-Policy
    - Missing X-Frame-Options or CSP frame-ancestors
    - Missing X-Content-Type-Options: nosniff
    - Missing Strict-Transport-Security (HTTPS only)
    - Server header revealing version info
    - X-Powered-By header present
    - Set-Cookie without HttpOnly flag
    - Set-Cookie without Secure flag (HTTPS only)

Usage::

    checker = SecurityHeaderChecker()
    findings = checker.check(url, response)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.utils.http import Response

log = get_logger("detector.headers")

# Version patterns in Server header (e.g. "Apache/2.4.51")
_SERVER_VERSION_RE = re.compile(
    r"(?:Apache|nginx|IIS|LiteSpeed|OpenResty|Tomcat|Jetty)"
    r"[/ ][\d.]+",
    re.IGNORECASE,
)


class SecurityHeaderChecker:
    """Passive security header analysis.

    Call ``check(url, response)`` on every page the crawler visits
    to produce findings for missing or insecure headers.
    """

    def check(self, url: str, response: Response) -> list[Finding]:
        """Run all header checks and return any findings."""
        findings: list[Finding] = []
        headers = response.headers
        is_https = url.startswith("https://")

        # ── Content-Security-Policy ────────────────────────────────
        if not self._has_header(headers, "content-security-policy"):
            findings.append(self._finding(
                url=url,
                title="Missing Content-Security-Policy Header",
                severity=SeverityLevel.LOW,
                evidence="No Content-Security-Policy header in response",
                cwe="CWE-693",
                remediation=(
                    "Add a Content-Security-Policy header to restrict which "
                    "sources of content the browser may load. Start with a "
                    "restrictive policy and relax as needed."
                ),
            ))

        # ── X-Frame-Options ────────────────────────────────────────
        has_xfo = self._has_header(headers, "x-frame-options")
        csp_val = self._get_header(headers, "content-security-policy")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower() if csp_val else False
        if not has_xfo and not has_frame_ancestors:
            findings.append(self._finding(
                url=url,
                title="Missing X-Frame-Options / CSP frame-ancestors",
                severity=SeverityLevel.LOW,
                evidence="No X-Frame-Options or CSP frame-ancestors directive",
                cwe="CWE-1021",
                remediation=(
                    "Set X-Frame-Options to DENY or SAMEORIGIN, or use the "
                    "CSP frame-ancestors directive to prevent clickjacking."
                ),
            ))

        # ── X-Content-Type-Options ─────────────────────────────────
        xcto = self._get_header(headers, "x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(self._finding(
                url=url,
                title="Missing X-Content-Type-Options: nosniff",
                severity=SeverityLevel.LOW,
                evidence=f"X-Content-Type-Options: {xcto or '(absent)'}",
                cwe="CWE-16",
                remediation=(
                    "Set X-Content-Type-Options: nosniff to prevent browsers "
                    "from MIME-sniffing a response away from the declared "
                    "content type."
                ),
            ))

        # ── Strict-Transport-Security (HTTPS only) ─────────────────
        if is_https and not self._has_header(headers, "strict-transport-security"):
            findings.append(self._finding(
                url=url,
                title="Missing Strict-Transport-Security Header",
                severity=SeverityLevel.MEDIUM,
                evidence="HTTPS page without HSTS header",
                cwe="CWE-319",
                remediation=(
                    "Set Strict-Transport-Security with a max-age of at "
                    "least 31536000 (one year) and includeSubDomains."
                ),
            ))

        # ── Server header version leak ─────────────────────────────
        server = self._get_header(headers, "server")
        if server and _SERVER_VERSION_RE.search(server):
            findings.append(self._finding(
                url=url,
                title="Server Header Reveals Version",
                severity=SeverityLevel.INFO,
                evidence=f"Server: {server}",
                cwe="CWE-200",
                remediation=(
                    "Remove or obfuscate the Server header to avoid "
                    "disclosing software version information to attackers."
                ),
            ))

        # ── X-Powered-By leak ──────────────────────────────────────
        powered_by = self._get_header(headers, "x-powered-by")
        if powered_by:
            findings.append(self._finding(
                url=url,
                title="X-Powered-By Header Present",
                severity=SeverityLevel.INFO,
                evidence=f"X-Powered-By: {powered_by}",
                cwe="CWE-200",
                remediation="Remove the X-Powered-By header from responses.",
            ))

        # ── Cookie checks ──────────────────────────────────────────
        findings.extend(self._check_cookies(url, headers, is_https))

        return findings

    # ── Cookie analysis ────────────────────────────────────────────

    @staticmethod
    def _check_cookies(
        url: str,
        headers: dict[str, str],
        is_https: bool,
    ) -> list[Finding]:
        """Check Set-Cookie headers for missing flags."""
        findings: list[Finding] = []

        # Headers dict may have a single set-cookie or be case-insensitive
        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue

            cookie_name = value.split("=", 1)[0].strip()
            flags_lower = value.lower()

            if "httponly" not in flags_lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' Without HttpOnly Flag",
                    severity=SeverityLevel.LOW,
                    url=url,
                    evidence=f"Set-Cookie: {value[:120]}",
                    cwe="CWE-1004",
                    remediation="Add the HttpOnly flag to prevent JavaScript access.",
                    confidence=0.9,
                    template_id="header-checker",
                ))

            if is_https and "secure" not in flags_lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' Without Secure Flag",
                    severity=SeverityLevel.LOW,
                    url=url,
                    evidence=f"Set-Cookie: {value[:120]}",
                    cwe="CWE-614",
                    remediation="Add the Secure flag to prevent cookie transmission over HTTP.",
                    confidence=0.9,
                    template_id="header-checker",
                ))

        return findings

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _has_header(headers: dict[str, str], name: str) -> bool:
        """Case-insensitive header presence check."""
        return any(k.lower() == name.lower() for k in headers)

    @staticmethod
    def _get_header(headers: dict[str, str], name: str) -> str:
        """Case-insensitive header value retrieval."""
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    @staticmethod
    def _finding(
        url: str,
        title: str,
        severity: SeverityLevel,
        evidence: str,
        cwe: str,
        remediation: str,
    ) -> Finding:
        """Build a header-checker Finding."""
        return Finding(
            title=title,
            severity=severity,
            url=url,
            evidence=evidence,
            cwe=cwe,
            owasp="A05:2021-Security Misconfiguration",
            remediation=remediation,
            confidence=0.9,
            template_id="header-checker",
        )
