"""Vulnerability classifier for Sentinal-Fuzz.

Enriches raw ``Finding`` objects with CVSS v3.1 scores, CWE/OWASP
mappings, business impact descriptions, step-by-step remediation,
and code-level fix examples.

Usage::

    from sentinal_fuzz.analyzer.classifier import VulnClassifier

    classifier = VulnClassifier()
    enriched = classifier.classify(finding)
    print(enriched.cvss_score, enriched.remediation_steps)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinal_fuzz.core.models import Finding, HttpExchange, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("classifier")


# ═══════════════════════════════════════════════════════════════════
# EnrichedFinding — extends Finding with analysis metadata
# ═══════════════════════════════════════════════════════════════════


@dataclass
class EnrichedFinding:
    """A vulnerability finding enriched with CVSS, CWE, and remediation data.

    Extends the base ``Finding`` fields with structured classification
    metadata used by reporters and the prioritizer.
    """

    # ── Inherited from Finding ─────────────────────────────────────
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

    # ── Enrichment fields ──────────────────────────────────────────
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    owasp_category: str = ""
    business_impact: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    code_example_fix: str = ""
    exploit_difficulty: str = "medium"   # "easy" | "medium" | "hard"
    requires_auth: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize the enriched finding to a JSON-compatible dict."""
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
            # Enriched fields
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "business_impact": self.business_impact,
            "remediation_steps": self.remediation_steps,
            "code_example_fix": self.code_example_fix,
            "exploit_difficulty": self.exploit_difficulty,
            "requires_auth": self.requires_auth,
        }


# ═══════════════════════════════════════════════════════════════════
# Vulnerability Knowledge Base
# ═══════════════════════════════════════════════════════════════════

VULN_KNOWLEDGE_BASE: dict[str, dict[str, Any]] = {
    # ── XSS ────────────────────────────────────────────────────────
    "xss-reflected": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp_category": "A03:2021 \u2013 Injection",
        "business_impact": (
            "An attacker can steal session cookies and impersonate any user "
            "who clicks a malicious link. This can lead to complete account "
            "takeover without the victim's knowledge."
        ),
        "remediation_steps": [
            "Escape all user input before rendering it in HTML using your framework's built-in escaping",
            "Implement a Content Security Policy (CSP) header to prevent inline script execution",
            "Use HTTPOnly flag on session cookies to prevent JavaScript access",
            "Validate and whitelist acceptable input on the server side",
        ],
        "code_example_fix": (
            "# Python/Flask example\n"
            "from markupsafe import escape\n\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    query = escape(request.args.get('q', ''))\n"
            "    return render_template('results.html', query=query)"
        ),
        "exploit_difficulty": "easy",
        "requires_auth": False,
    },

    # ── SQL Injection — Error-Based ────────────────────────────────
    "sqli-error": {
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 \u2013 Injection",
        "business_impact": (
            "An attacker can extract the entire database contents including "
            "user credentials, personal data, and financial records. Error "
            "messages reveal table structure, accelerating the attack."
        ),
        "remediation_steps": [
            "Use parameterised queries (prepared statements) for ALL database access",
            "Never concatenate user input into SQL strings",
            "Apply least-privilege database accounts — the app should not use 'root' or 'sa'",
            "Disable verbose error messages in production (use generic error pages)",
            "Deploy a Web Application Firewall (WAF) as a defense-in-depth measure",
        ],
        "code_example_fix": (
            "# Python/SQLAlchemy — parameterised query\n"
            "from sqlalchemy import text\n\n"
            "result = db.execute(\n"
            '    text("SELECT * FROM users WHERE id = :user_id"),\n'
            '    {"user_id": request.args.get("id")},\n'
            ")"
        ),
        "exploit_difficulty": "easy",
        "requires_auth": False,
    },

    # ── SQL Injection — Time-Based Blind ───────────────────────────
    "sqli-time": {
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 \u2013 Injection",
        "business_impact": (
            "An attacker can extract sensitive data one bit at a time by "
            "observing response delays. While slower than error-based SQLi, "
            "blind injection is fully automatable and equally devastating."
        ),
        "remediation_steps": [
            "Use parameterised queries (prepared statements) for ALL database access",
            "Never concatenate user input into SQL strings",
            "Apply query execution timeouts to limit blind injection impact",
            "Implement connection pool limits to reduce denial-of-service risk",
            "Monitor application logs for unusually slow queries",
        ],
        "code_example_fix": (
            "# Node.js/PostgreSQL — parameterised query\n"
            "const { rows } = await pool.query(\n"
            "  'SELECT * FROM products WHERE category = $1',\n"
            "  [req.query.category]\n"
            ");"
        ),
        "exploit_difficulty": "medium",
        "requires_auth": False,
    },

    # ── SSRF ───────────────────────────────────────────────────────
    "ssrf-basic": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "owasp_category": "A10:2021 \u2013 Server-Side Request Forgery",
        "business_impact": (
            "An attacker can make the server send requests to internal "
            "systems, cloud metadata endpoints (AWS/GCP/Azure), or other "
            "services behind the firewall. This can expose API keys, "
            "instance credentials, and internal network topology."
        ),
        "remediation_steps": [
            "Validate and whitelist destination URLs and hostnames on the server side",
            "Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)",
            "Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)",
            "Use DNS resolution checks to prevent DNS-rebinding attacks",
            "Run outbound HTTP requests through a proxy with network-level restrictions",
        ],
        "code_example_fix": (
            "# Python — URL validation with allowlist\n"
            "import ipaddress\n"
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n\n"
            "def validate_url(url: str) -> bool:\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.hostname not in ALLOWED_HOSTS:\n"
            "        raise ValueError(f'Host {parsed.hostname} not allowed')\n"
            "    ip = ipaddress.ip_address(parsed.hostname)\n"
            "    if ip.is_private or ip.is_loopback:\n"
            "        raise ValueError('Internal IPs blocked')\n"
            "    return True"
        ),
        "exploit_difficulty": "medium",
        "requires_auth": False,
    },

    # ── SSTI ───────────────────────────────────────────────────────
    "ssti-basic": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-1336",
        "cwe_name": "Improper Neutralization of Special Elements Used in a Template Engine",
        "owasp_category": "A03:2021 \u2013 Injection",
        "business_impact": (
            "An attacker can execute arbitrary code on the server through "
            "the template engine, leading to full remote code execution. "
            "This typically results in complete server compromise, data "
            "exfiltration, and lateral movement into the internal network."
        ),
        "remediation_steps": [
            "Never pass user input directly into template rendering functions",
            "Use a sandboxed template engine (e.g. Jinja2 SandboxedEnvironment)",
            "Avoid user-controlled template strings entirely — use pre-defined templates with variables",
            "Validate that input does not contain template syntax characters ({{ }}, <% %>, etc.)",
            "Run the application with minimal filesystem and network permissions",
        ],
        "code_example_fix": (
            "# Python/Jinja2 — SAFE: use render_template, not from_string\n"
            "from flask import render_template\n\n"
            "# VULNERABLE (never do this):\n"
            "# template = Template(user_input)\n"
            "# return template.render()\n\n"
            "# SAFE:\n"
            "@app.route('/greet')\n"
            "def greet():\n"
            "    name = request.args.get('name', 'World')\n"
            "    return render_template('greet.html', name=name)"
        ),
        "exploit_difficulty": "medium",
        "requires_auth": False,
    },

    # ── Path Traversal ─────────────────────────────────────────────
    "path-traversal": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "owasp_category": "A01:2021 \u2013 Broken Access Control",
        "business_impact": (
            "An attacker can read arbitrary files from the server including "
            "source code, configuration files with database passwords, "
            "private keys, and /etc/passwd. In combination with file upload "
            "vulnerabilities this can escalate to remote code execution."
        ),
        "remediation_steps": [
            "Validate and sanitise file path input — reject paths containing '..' or null bytes",
            "Use an allowlist of permitted file names or paths instead of user-controlled paths",
            "Resolve symbolic links and ensure the canonical path stays within the intended directory",
            "Run the application with least-privilege filesystem permissions",
            "Use chroot or containerisation to restrict filesystem access",
        ],
        "code_example_fix": (
            "# Python — safe file serving with path validation\n"
            "import os\n"
            "from pathlib import Path\n\n"
            "SAFE_DIR = Path('/var/app/uploads').resolve()\n\n"
            "def serve_file(filename: str):\n"
            "    filepath = (SAFE_DIR / filename).resolve()\n"
            "    if not filepath.is_relative_to(SAFE_DIR):\n"
            "        abort(403)  # Path traversal attempt\n"
            "    return send_file(filepath)"
        ),
        "exploit_difficulty": "easy",
        "requires_auth": False,
    },

    # ── Open Redirect ──────────────────────────────────────────────
    "open-redirect": {
        "cvss_score": 4.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cwe_id": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site",
        "owasp_category": "A01:2021 \u2013 Broken Access Control",
        "business_impact": (
            "An attacker can craft phishing links that appear to originate "
            "from a trusted domain. Victims clicking these links are "
            "redirected to malicious sites designed to steal credentials. "
            "This damages brand trust and enables social engineering attacks."
        ),
        "remediation_steps": [
            "Validate redirect targets against a whitelist of allowed domains and paths",
            "Use relative paths for internal redirects instead of absolute URLs",
            "If a redirect parameter is necessary, map it through an index/enum rather than accepting raw URLs",
            "Display an interstitial warning page before redirecting to external domains",
        ],
        "code_example_fix": (
            "# Python/Flask — safe redirect with allowlist\n"
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_REDIRECT_HOSTS = {'example.com', 'app.example.com'}\n\n"
            "@app.route('/redirect')\n"
            "def safe_redirect():\n"
            "    target = request.args.get('url', '/')\n"
            "    parsed = urlparse(target)\n"
            "    if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_HOSTS:\n"
            "        abort(400, 'External redirect not allowed')\n"
            "    return redirect(target)"
        ),
        "exploit_difficulty": "easy",
        "requires_auth": False,
    },

    # ── Security Headers (passive) ─────────────────────────────────
    "security-headers": {
        "cvss_score": 2.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp_category": "A05:2021 \u2013 Security Misconfiguration",
        "business_impact": (
            "Missing security headers leave the application vulnerable to "
            "clickjacking (X-Frame-Options), MIME-type attacks "
            "(X-Content-Type-Options), and protocol downgrade attacks "
            "(Strict-Transport-Security). These amplify the impact of "
            "other vulnerabilities."
        ),
        "remediation_steps": [
            "Add Content-Security-Policy header with a strict policy (default-src 'self')",
            "Add Strict-Transport-Security header with max-age=31536000 and includeSubDomains",
            "Add X-Frame-Options header set to DENY or SAMEORIGIN",
            "Add X-Content-Type-Options header set to nosniff",
            "Add Referrer-Policy header set to strict-origin-when-cross-origin",
            "Add Permissions-Policy header to restrict browser features",
        ],
        "code_example_fix": (
            "# Nginx configuration\n"
            "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "add_header X-Frame-Options \"DENY\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
        ),
        "exploit_difficulty": "hard",
        "requires_auth": False,
    },

    # ── Sensitive Data Exposure (passive) ──────────────────────────
    "sensitive-exposure": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_category": "A01:2021 \u2013 Broken Access Control",
        "business_impact": (
            "Exposed API keys, stack traces, or internal paths give attackers "
            "a roadmap to the application's infrastructure. Leaked credentials "
            "can be used immediately for unauthorized access. Stack traces "
            "reveal framework versions, enabling targeted exploits."
        ),
        "remediation_steps": [
            "Remove API keys, secrets, and tokens from response bodies — use environment variables",
            "Disable debug mode and verbose error pages in production",
            "Scrub internal IP addresses and stack traces from all error responses",
            "Implement a custom error handler that returns generic error messages",
            "Rotate any credentials that may have been publicly exposed",
        ],
        "code_example_fix": (
            "# Python/Flask — custom error handler\n"
            "import logging\n\n"
            "@app.errorhandler(500)\n"
            "def internal_error(error):\n"
            "    logging.exception('Internal server error')  # Log full trace\n"
            "    return {'error': 'An internal error occurred'}, 500  # Generic response"
        ),
        "exploit_difficulty": "easy",
        "requires_auth": False,
    },
}


# ═══════════════════════════════════════════════════════════════════
# VulnClassifier
# ═══════════════════════════════════════════════════════════════════


class VulnClassifier:
    """Enriches raw findings with CVSS, CWE, OWASP, and remediation data.

    Looks up each finding's ``template_id`` in the ``VULN_KNOWLEDGE_BASE``
    and produces an ``EnrichedFinding`` with all classification fields
    populated.

    Usage::

        classifier = VulnClassifier()
        enriched = classifier.classify(finding)
    """

    def __init__(
        self,
        knowledge_base: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._kb = knowledge_base or VULN_KNOWLEDGE_BASE

    def classify(self, finding: Finding) -> EnrichedFinding:
        """Classify a single Finding and return an EnrichedFinding.

        If the template_id is not found in the knowledge base, the
        enriched fields are left at their defaults (zero/empty) and
        a warning is logged.

        Args:
            finding: The raw finding from the fuzzing engine.

        Returns:
            An ``EnrichedFinding`` with all classification metadata.
        """
        kb_entry = self._kb.get(finding.template_id, {})

        if not kb_entry:
            log.warning(
                "No knowledge base entry for template_id='%s' — "
                "enriched fields will be empty",
                finding.template_id,
            )

        return EnrichedFinding(
            # Pass through all Finding fields
            title=finding.title,
            severity=finding.severity,
            url=finding.url,
            parameter=finding.parameter,
            payload=finding.payload,
            evidence=finding.evidence,
            request=finding.request,
            response=finding.response,
            cwe=finding.cwe or kb_entry.get("cwe_id", ""),
            owasp=finding.owasp or kb_entry.get("owasp_category", ""),
            remediation=finding.remediation,
            confidence=finding.confidence,
            template_id=finding.template_id,
            id=finding.id,
            timestamp=finding.timestamp,
            # Enrichment fields from knowledge base
            cvss_score=kb_entry.get("cvss_score", 0.0),
            cvss_vector=kb_entry.get("cvss_vector", ""),
            cwe_id=kb_entry.get("cwe_id", ""),
            cwe_name=kb_entry.get("cwe_name", ""),
            owasp_category=kb_entry.get("owasp_category", ""),
            business_impact=kb_entry.get("business_impact", ""),
            remediation_steps=kb_entry.get("remediation_steps", []),
            code_example_fix=kb_entry.get("code_example_fix", ""),
            exploit_difficulty=kb_entry.get("exploit_difficulty", "medium"),
            requires_auth=kb_entry.get("requires_auth", False),
        )

    def classify_all(
        self, findings: list[Finding],
    ) -> list[EnrichedFinding]:
        """Classify a list of findings.

        Args:
            findings: Raw findings from the fuzzing engine.

        Returns:
            List of ``EnrichedFinding`` objects.
        """
        return [self.classify(f) for f in findings]
