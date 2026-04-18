"""Beautiful, self-contained HTML report generator for Sentinal-Fuzz.

Produces a single-file HTML report with:
- Dark theme security-tool aesthetic
- No external dependencies (all CSS/JS inlined)
- Responsive design (mobile-friendly)
- CSS-only donut chart for severity breakdown
- Collapsible finding cards using <details> tags
- Print-friendly CSS media query
- Plain-English explanations for each finding

Usage::

    from sentinal_fuzz.reporter.html_reporter import HtmlReporter

    reporter = HtmlReporter(output_dir="reports")
    filepath = reporter.generate(scan_result)
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinal_fuzz.core.models import (
    Finding,
    ScanResult,
    SeverityLevel,
)
from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.reporter.json_reporter import _compute_risk_score
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("html_reporter")

# ── Severity → display config ─────────────────────────────────────

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff4757",
    "high": "#ff6b35",
    "medium": "#ffa502",
    "low": "#3b82f6",
    "info": "#6b7280",
}

_SEVERITY_LABELS: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# ── Plain-English explanations ─────────────────────────────────────

_WHAT_THIS_MEANS: dict[str, str] = {
    "xss-reflected": (
        "An attacker can inject malicious scripts into your web pages. "
        "When another user visits the affected page, the script runs in "
        "their browser and can steal their session, redirect them to a "
        "fake login page, or perform actions on their behalf."
    ),
    "sqli-error": (
        "Your application is directly inserting user input into database "
        "queries. An attacker can modify these queries to read, modify, or "
        "delete any data in your database — including user passwords, "
        "personal information, and financial records."
    ),
    "sqli-time": (
        "Your application appears vulnerable to blind SQL injection. An "
        "attacker can extract data from your database one character at a "
        "time by measuring response delays. This is slower than error-based "
        "SQLi but just as dangerous."
    ),
    "path-traversal": (
        "An attacker can read arbitrary files from your server by manipulating "
        "file path parameters. This could expose configuration files, source "
        "code, password files, or other sensitive system data."
    ),
    "ssti-basic": (
        "Your application evaluates user input as template code on the server. "
        "An attacker can execute arbitrary code on your server, potentially "
        "taking complete control of the system."
    ),
    "ssrf-basic": (
        "Your server can be tricked into making requests to internal services "
        "or cloud metadata endpoints. An attacker could access internal APIs, "
        "steal cloud credentials, or scan your internal network."
    ),
    "open-redirect": (
        "Your application redirects users to URLs supplied in parameters "
        "without validation. An attacker can craft links that appear to come "
        "from your site but send users to phishing pages."
    ),
    "security-headers": (
        "Your application is missing important security headers that protect "
        "against common attacks like clickjacking, MIME-type sniffing, and "
        "cross-site scripting."
    ),
    "sensitive-exposure": (
        "Sensitive information like API keys, error details, or internal IP "
        "addresses is visible in your application's responses. This gives "
        "attackers valuable intelligence for further attacks."
    ),
}

_ATTACK_SCENARIO: dict[str, str] = {
    "xss-reflected": (
        "An attacker sends a victim a link containing a hidden script. "
        "When clicked, the script steals the victim's login session cookie."
    ),
    "sqli-error": (
        "An attacker types a specially-crafted string into a search box "
        "and dumps the entire user database, including hashed passwords."
    ),
    "sqli-time": (
        "An attacker uses automated tools to extract your database contents "
        "by timing how long each response takes."
    ),
    "path-traversal": (
        "An attacker changes a file parameter to '../../../../etc/passwd' "
        "and reads your server's password file."
    ),
    "ssti-basic": (
        "An attacker injects template code like '{{config}}' to dump server "
        "configuration, then escalates to full remote code execution."
    ),
    "ssrf-basic": (
        "An attacker submits 'http://169.254.169.254/latest/meta-data/' as a "
        "URL parameter and steals your AWS access keys."
    ),
    "open-redirect": (
        "An attacker crafts a link like 'yoursite.com/login?next=evil.com' "
        "to phish users who trust your domain."
    ),
    "security-headers": (
        "Without X-Frame-Options, an attacker embeds your login page in an "
        "invisible iframe and tricks users into clicking hidden buttons."
    ),
    "sensitive-exposure": (
        "An attacker finds an AWS key in an API response and uses it to "
        "access your S3 buckets and download customer data."
    ),
}

_FIX_EXAMPLES: dict[str, str] = {
    "xss-reflected": (
        '# Python (Jinja2) — auto-escaping is on by default\n'
        '# In your template:\n'
        '&lt;p&gt;{{ user_input }}&lt;/p&gt;  &lt;!-- Jinja2 auto-escapes this --&gt;\n\n'
        '# If you must render raw HTML, sanitize first:\n'
        'import bleach\n'
        'clean = bleach.clean(user_input, tags=["b", "i", "em"])\n'
    ),
    "sqli-error": (
        '# Python (SQLAlchemy) — parameterized query\n'
        'result = db.execute(\n'
        '    text("SELECT * FROM users WHERE id = :user_id"),\n'
        '    {"user_id": request.args["id"]}\n'
        ')\n\n'
        '# NEVER do this:\n'
        '# db.execute(f"SELECT * FROM users WHERE id = {user_input}")  # DANGER\n'
    ),
    "sqli-time": (
        '# Same fix as error-based SQLi — use parameterized queries:\n'
        'cursor.execute(\n'
        '    "SELECT * FROM products WHERE id = %s",\n'
        '    (product_id,)  # Parameter passed separately\n'
        ')\n'
    ),
    "path-traversal": (
        '# Python — validate file path stays within allowed directory\n'
        'import os\n\n'
        'ALLOWED_DIR = "/app/uploads"\n'
        'requested = os.path.realpath(os.path.join(ALLOWED_DIR, filename))\n'
        'if not requested.startswith(ALLOWED_DIR):\n'
        '    raise ValueError("Path traversal detected")\n'
    ),
    "ssti-basic": (
        '# Python (Flask) — render from file, never from user string\n'
        '# SAFE:\n'
        'return render_template("page.html", name=user_input)\n\n'
        '# DANGEROUS (never do this):\n'
        '# return render_template_string(user_input)  # RCE risk!\n'
    ),
    "ssrf-basic": (
        '# Python — validate URLs against allowlist\n'
        'from urllib.parse import urlparse\n\n'
        'ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\n'
        'parsed = urlparse(user_url)\n'
        'if parsed.hostname not in ALLOWED_HOSTS:\n'
        '    raise ValueError("URL not allowed")\n'
    ),
    "open-redirect": (
        '# Python (Flask) — validate redirect target\n'
        'from urllib.parse import urlparse\n\n'
        'target = request.args.get("next", "/")\n'
        'parsed = urlparse(target)\n'
        'if parsed.netloc and parsed.netloc != request.host:\n'
        '    target = "/"  # Block external redirects\n'
        'return redirect(target)\n'
    ),
    "security-headers": (
        '# Python (Flask) — add security headers\n'
        '@app.after_request\n'
        'def add_security_headers(response):\n'
        '    response.headers["X-Frame-Options"] = "DENY"\n'
        '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
        '    response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
        '    return response\n'
    ),
    "sensitive-exposure": (
        '# Python — configure production error handling\n'
        'app.config["DEBUG"] = False  # Never True in production\n'
        'app.config["PROPAGATE_EXCEPTIONS"] = False\n\n'
        '# Use environment variables for secrets:\n'
        'API_KEY = os.environ["API_KEY"]  # Never hardcoded\n'
    ),
}


@dataclass
class HtmlReporter(BaseReporter):
    """Generate a beautiful, self-contained HTML report."""

    @property
    def file_extension(self) -> str:
        return ".html"

    @property
    def format_name(self) -> str:
        return "HTML"

    def generate(self, result: ScanResult) -> str:
        """Generate the HTML report and write to disk.

        Args:
            result: The complete scan result.

        Returns:
            Absolute file path of the generated HTML report.
        """
        html_content = self._render(result)
        filename = self._build_filename(result)
        filepath = self._write_file(filename, html_content)
        log.info("HTML report generated: %s", filepath)
        return filepath

    def _render(self, result: ScanResult) -> str:
        """Render the complete HTML document."""
        risk_score = _compute_risk_score(result)
        severity_counts = _severity_counts(result)
        sorted_findings = sorted(
            result.findings,
            key=lambda f: _severity_order(f.severity),
        )
        scan_date = result.start_time.strftime("%B %d, %Y at %H:%M")
        duration = f"{result.duration_seconds:.1f}s"

        findings_html = "\n".join(
            _render_finding_card(f, idx)
            for idx, f in enumerate(sorted_findings)
        )

        endpoints_html = _render_endpoints_table(result)
        donut_html = _render_donut_chart(severity_counts)
        executive_summary = _render_executive_summary(result, risk_score)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinal-Fuzz Security Report — {_esc(result.target)}</title>
{_CSS}
</head>
<body>

<!-- ═══ HEADER ═══════════════════════════════════════════════ -->
<header class="report-header">
  <div class="header-brand">
    <h1>🛡️ Sentinal-Fuzz</h1>
    <span class="header-subtitle">Dynamic Application Security Testing Report</span>
  </div>
  <div class="header-meta">
    <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{_esc(result.target)}</span></div>
    <div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">{scan_date}</span></div>
    <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{duration}</span></div>
    <div class="meta-item"><span class="meta-label">Findings</span><span class="meta-value findings-count">{len(result.findings)}</span></div>
  </div>
</header>

<!-- ═══ EXECUTIVE SUMMARY ════════════════════════════════════ -->
<section class="exec-summary">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-text">
      {executive_summary}
    </div>
    <div class="summary-chart">
      {donut_html}
      <div class="risk-score">
        <div class="risk-value {_risk_class(risk_score)}">{risk_score}</div>
        <div class="risk-label">Risk Score</div>
      </div>
    </div>
  </div>
</section>

<!-- ═══ FINDINGS ═════════════════════════════════════════════ -->
<section class="findings-section">
  <h2>Vulnerability Findings ({len(result.findings)})</h2>
  {findings_html if findings_html else '<p class="no-findings">✅ No vulnerabilities found. Great job!</p>'}
</section>

<!-- ═══ ENDPOINT MAP ═════════════════════════════════════════ -->
<section class="endpoints-section">
  <details>
    <summary><h2 style="display:inline">Endpoint Map ({len(result.endpoints)} endpoints)</h2></summary>
    {endpoints_html}
  </details>
</section>

<!-- ═══ SCAN STATISTICS ══════════════════════════════════════ -->
<section class="stats-section">
  <h2>Scan Statistics</h2>
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{result.stats.total_requests}</div>
      <div class="stat-label">HTTP Requests</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{result.stats.endpoints_found}</div>
      <div class="stat-label">Endpoints</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{result.stats.requests_per_second:.1f}</div>
      <div class="stat-label">Req/sec</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{duration}</div>
      <div class="stat-label">Duration</div>
    </div>
  </div>
</section>

<footer class="report-footer">
  <p>Generated by <strong>Sentinal-Fuzz v{result.scanner_version}</strong> · Scan ID: {result.scan_id}</p>
</footer>

</body>
</html>"""


# ── Rendering helpers ──────────────────────────────────────────────


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text))


def _severity_order(severity: SeverityLevel) -> int:
    """Return sort order (0=critical → 4=info)."""
    order = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 4,
    }
    return order.get(severity, 5)


def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts = {level.value: 0 for level in SeverityLevel}
    for f in result.findings:
        counts[f.severity.value] += 1
    return counts


def _risk_class(score: int) -> str:
    if score >= 75:
        return "risk-critical"
    if score >= 50:
        return "risk-high"
    if score >= 25:
        return "risk-medium"
    return "risk-low"


def _render_executive_summary(result: ScanResult, risk_score: int) -> str:
    total = len(result.findings)
    if total == 0:
        return (
            "<p>The scan completed successfully and <strong>no vulnerabilities</strong> "
            "were identified. The target application appears to handle user input safely "
            "based on the test coverage achieved. Continue monitoring with regular scans.</p>"
        )

    critical = sum(1 for f in result.findings if f.severity == SeverityLevel.CRITICAL)
    high = sum(1 for f in result.findings if f.severity == SeverityLevel.HIGH)

    severity_word = "low-risk"
    if critical > 0:
        severity_word = "critical"
    elif high > 0:
        severity_word = "significant"

    top = None
    for f in sorted(result.findings, key=lambda x: _severity_order(x.severity)):
        top = f
        break

    summary = (
        f"<p>The scan identified <strong>{total} security issue{'s' if total != 1 else ''}</strong> "
        f"across the target application, with an overall risk score of <strong>{risk_score}/100</strong>. "
    )
    if critical > 0:
        summary += (
            f"There {'are' if critical > 1 else 'is'} <strong class=\"sev-critical\">"
            f"{critical} critical</strong> finding{'s' if critical > 1 else ''} "
            f"that require{'s' if critical == 1 else ''} immediate attention. "
        )
    if high > 0:
        summary += (
            f"Additionally, <strong class=\"sev-high\">{high} high-severity</strong> "
            f"issue{'s' if high > 1 else ''} should be addressed as a priority. "
        )
    summary += "</p>"

    if top:
        summary += (
            f'<div class="most-critical">'
            f'<span class="mc-label">⚠️ Most Critical:</span> '
            f'<span class="mc-title">{_esc(top.title)}</span> '
            f'at <code>{_esc(top.url)}</code>'
            f'</div>'
        )

    return summary


def _render_donut_chart(counts: dict[str, int]) -> str:
    """Render a CSS-only donut chart."""
    total = sum(counts.values())
    if total == 0:
        return '<div class="donut-chart"><div class="donut-empty">No findings</div></div>'

    # Build conic-gradient segments
    segments = []
    offset = 0
    for sev in ("critical", "high", "medium", "low", "info"):
        count = counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / total) * 100
        color = _SEVERITY_COLORS[sev]
        segments.append(f"{color} {offset:.1f}% {offset + pct:.1f}%")
        offset += pct

    gradient = ", ".join(segments)

    legend_items = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        count = counts.get(sev, 0)
        if count == 0:
            continue
        color = _SEVERITY_COLORS[sev]
        label = _SEVERITY_LABELS[sev]
        legend_items += (
            f'<div class="legend-item">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'{label}: {count}'
            f'</div>'
        )

    return f"""
    <div class="donut-wrapper">
      <div class="donut-chart" style="background: conic-gradient({gradient})">
        <div class="donut-hole">{total}</div>
      </div>
      <div class="donut-legend">{legend_items}</div>
    </div>
    """


def _render_finding_card(finding: Finding, idx: int) -> str:
    """Render a single finding as a collapsible card."""
    sev = finding.severity.value
    color = _SEVERITY_COLORS.get(sev, "#6b7280")
    label = _SEVERITY_LABELS.get(sev, sev.title())
    tid = finding.template_id

    what_means = _WHAT_THIS_MEANS.get(tid, (
        "This vulnerability could allow an attacker to compromise part of "
        "your application. Review the technical details below for specifics."
    ))
    attack = _ATTACK_SCENARIO.get(tid, (
        "An attacker could exploit this vulnerability to gain unauthorized "
        "access or extract sensitive data."
    ))
    fix_code = _FIX_EXAMPLES.get(tid, "")
    remediation = finding.remediation or "Review the finding details and apply appropriate security controls."

    # Build fix steps from remediation text
    fix_steps = _remediation_to_steps(remediation)

    # Technical details
    tech_details = _render_tech_details(finding)

    return f"""
    <details class="finding-card" id="finding-{idx}">
      <summary class="finding-summary">
        <span class="severity-badge" style="background:{color}">{label}</span>
        <span class="finding-title">{_esc(finding.title)}</span>
        <span class="finding-url">{_esc(finding.url)}</span>
        {f'<span class="finding-param">param: {_esc(finding.parameter)}</span>' if finding.parameter else ''}
      </summary>
      <div class="finding-body">

        <div class="finding-section">
          <h4>🔍 What This Means</h4>
          <p>{what_means}</p>
        </div>

        <div class="finding-section">
          <h4>⚔️ How an Attacker Could Use This</h4>
          <p>{attack}</p>
        </div>

        <div class="finding-section">
          <h4>🛠️ How to Fix It</h4>
          {fix_steps}
          {f'<pre class="code-block"><code>{fix_code}</code></pre>' if fix_code else ''}
        </div>

        <details class="tech-details">
          <summary>📋 Technical Details</summary>
          {tech_details}
        </details>

      </div>
    </details>
    """


def _remediation_to_steps(text: str) -> str:
    """Convert remediation text into numbered steps."""
    sentences = [s.strip() for s in text.replace(". ", ".\n").split("\n") if s.strip()]
    if len(sentences) <= 1:
        return f"<p>{_esc(text)}</p>"
    items = "\n".join(f"<li>{_esc(s)}</li>" for s in sentences)
    return f"<ol class='fix-steps'>{items}</ol>"


def _render_tech_details(finding: Finding) -> str:
    """Render the collapsible technical details section."""
    rows = []
    if finding.cwe:
        rows.append(f"<tr><td>CWE</td><td><code>{_esc(finding.cwe)}</code></td></tr>")
    if finding.owasp:
        rows.append(f"<tr><td>OWASP</td><td><code>{_esc(finding.owasp)}</code></td></tr>")
    rows.append(f"<tr><td>Confidence</td><td>{finding.confidence:.0%}</td></tr>")
    rows.append(f"<tr><td>Template</td><td><code>{_esc(finding.template_id)}</code></td></tr>")
    if finding.payload:
        rows.append(f"<tr><td>Payload</td><td><code>{_esc(finding.payload[:200])}</code></td></tr>")
    if finding.evidence:
        rows.append(f"<tr><td>Evidence</td><td><code>{_esc(finding.evidence[:300])}</code></td></tr>")

    table = f"<table class='tech-table'>{''.join(rows)}</table>"

    # Request/response evidence
    evidence_block = ""
    if finding.request:
        req = finding.request
        evidence_block += (
            f"<div class='evidence-block'>"
            f"<h5>Request</h5>"
            f"<pre><code>{_esc(req.method)} {_esc(req.url)}\n"
        )
        for k, v in req.request_headers.items():
            evidence_block += f"{_esc(k)}: {_esc(v)}\n"
        if req.request_body:
            evidence_block += f"\n{_esc(req.request_body[:500])}"
        evidence_block += "</code></pre></div>"

    if finding.response:
        evidence_block += (
            f"<div class='evidence-block'>"
            f"<h5>Response</h5>"
            f"<pre><code>{_esc(finding.response[:1000])}</code></pre></div>"
        )

    return table + evidence_block


def _render_endpoints_table(result: ScanResult) -> str:
    """Render the full endpoint map table."""
    if not result.endpoints:
        return "<p>No endpoints discovered.</p>"

    rows = ""
    for ep in result.endpoints:
        params = ", ".join(ep.injectable_params) or "—"
        rows += (
            f"<tr>"
            f"<td><span class='method-badge method-{ep.method.lower()}'>{_esc(ep.method)}</span></td>"
            f"<td>{_esc(ep.url)}</td>"
            f"<td>{_esc(params)}</td>"
            f"<td>{_esc(ep.source)}</td>"
            f"</tr>"
        )

    return f"""
    <table class="endpoints-table">
      <thead>
        <tr><th>Method</th><th>URL</th><th>Parameters</th><th>Source</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    """


# ── Inline CSS ─────────────────────────────────────────────────────

_CSS = """<style>
/* ── Reset & base ─────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 15px; }
body {
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
  background: #0f1117;
  color: #e2e8f0;
  line-height: 1.65;
  max-width: 1100px;
  margin: 0 auto;
  padding: 1.5rem;
}
h1, h2, h3, h4, h5 { color: #f1f5f9; font-weight: 600; }
h2 { font-size: 1.5rem; margin-bottom: 1rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }
a { color: #60a5fa; text-decoration: none; }
code { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.9em; background: #1e293b; padding: 0.15em 0.4em; border-radius: 4px; }
pre { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px; padding: 1rem; overflow-x: auto; margin: 0.5rem 0; }
pre code { background: transparent; padding: 0; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; }
th, td { text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #1e293b; }
th { background: #1a1f2e; color: #94a3b8; font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }

/* ── Header ───────────────────────────────────────── */
.report-header {
  background: linear-gradient(135deg, #1a1f2e 0%, #0f1117 100%);
  border: 1px solid #2d3748;
  border-radius: 12px;
  padding: 2rem;
  margin-bottom: 2rem;
}
.header-brand h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
.header-subtitle { color: #64748b; font-size: 0.95rem; }
.header-meta { display: flex; flex-wrap: wrap; gap: 1.5rem; margin-top: 1.5rem; }
.meta-item { display: flex; flex-direction: column; }
.meta-label { color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
.meta-value { font-size: 1.1rem; font-weight: 500; }
.findings-count { color: #ff4757; font-weight: 700; }

/* ── Executive Summary ────────────────────────────── */
.exec-summary {
  background: #1a1f2e;
  border: 1px solid #2d3748;
  border-radius: 12px;
  padding: 2rem;
  margin-bottom: 2rem;
}
.summary-grid { display: grid; grid-template-columns: 1fr auto; gap: 2rem; align-items: start; }
.summary-text p { margin-bottom: 0.75rem; line-height: 1.7; }
.sev-critical { color: #ff4757; }
.sev-high { color: #ff6b35; }
.most-critical {
  background: #2d1b1b;
  border-left: 3px solid #ff4757;
  padding: 0.75rem 1rem;
  border-radius: 0 6px 6px 0;
  margin-top: 1rem;
}
.mc-label { font-weight: 600; color: #ff4757; }
.mc-title { font-weight: 500; }

/* ── Donut Chart ──────────────────────────────────── */
.donut-wrapper { display: flex; flex-direction: column; align-items: center; gap: 1rem; }
.donut-chart {
  width: 140px; height: 140px;
  border-radius: 50%;
  position: relative;
  display: flex; align-items: center; justify-content: center;
}
.donut-hole {
  width: 80px; height: 80px;
  background: #1a1f2e;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.8rem; font-weight: 700; color: #f1f5f9;
}
.donut-empty { color: #64748b; font-size: 0.85rem; text-align: center; padding: 3rem 0; }
.donut-legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; justify-content: center; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; color: #94a3b8; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

/* ── Risk Score ───────────────────────────────────── */
.risk-score { text-align: center; margin-top: 1rem; }
.risk-value { font-size: 2.5rem; font-weight: 800; }
.risk-label { color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }
.risk-critical { color: #ff4757; }
.risk-high { color: #ff6b35; }
.risk-medium { color: #ffa502; }
.risk-low { color: #22c55e; }

/* ── Finding Cards ────────────────────────────────── */
.findings-section { margin-bottom: 2rem; }
.no-findings { text-align: center; padding: 3rem; color: #22c55e; font-size: 1.2rem; }

.finding-card {
  background: #1a1f2e;
  border: 1px solid #2d3748;
  border-radius: 10px;
  margin-bottom: 0.75rem;
  overflow: hidden;
  transition: border-color 0.2s;
}
.finding-card[open] { border-color: #475569; }
.finding-card:hover { border-color: #475569; }

.finding-summary {
  padding: 1rem 1.25rem;
  cursor: pointer;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 0.75rem;
  list-style: none;
}
.finding-summary::-webkit-details-marker { display: none; }

.severity-badge {
  display: inline-block;
  padding: 0.2rem 0.65rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #fff;
  flex-shrink: 0;
}
.finding-title { font-weight: 600; flex-shrink: 0; }
.finding-url { color: #64748b; font-size: 0.85rem; word-break: break-all; }
.finding-param { color: #94a3b8; font-size: 0.8rem; background: #2d3748; padding: 0.1rem 0.5rem; border-radius: 3px; }

.finding-body { padding: 0.5rem 1.25rem 1.5rem; }
.finding-section { margin-bottom: 1.25rem; }
.finding-section h4 { font-size: 1rem; margin-bottom: 0.5rem; color: #cbd5e1; }
.finding-section p { color: #94a3b8; }
.fix-steps { padding-left: 1.5rem; color: #94a3b8; }
.fix-steps li { margin-bottom: 0.3rem; }
.code-block { font-size: 0.85rem; }

/* ── Tech Details ─────────────────────────────────── */
.tech-details {
  background: #151922;
  border: 1px solid #2d3748;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  margin-top: 1rem;
}
.tech-details summary { cursor: pointer; color: #64748b; font-size: 0.9rem; }
.tech-details[open] summary { margin-bottom: 0.75rem; }
.tech-table td:first-child { color: #64748b; width: 120px; font-size: 0.85rem; }
.evidence-block { margin-top: 0.75rem; }
.evidence-block h5 { color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.3rem; }

/* ── Endpoints ────────────────────────────────────── */
.endpoints-section { margin-bottom: 2rem; }
.endpoints-section details { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 10px; padding: 1rem 1.5rem; }
.endpoints-section summary { cursor: pointer; }
.endpoints-table { margin-top: 1rem; }
.method-badge { font-weight: 700; font-size: 0.8rem; padding: 0.15rem 0.5rem; border-radius: 3px; }
.method-get { color: #22c55e; }
.method-post { color: #3b82f6; }
.method-put { color: #f59e0b; }
.method-delete { color: #ef4444; }

/* ── Stats ────────────────────────────────────────── */
.stats-section { margin-bottom: 2rem; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 1rem; }
.stat-card {
  background: #1a1f2e;
  border: 1px solid #2d3748;
  border-radius: 10px;
  padding: 1.25rem;
  text-align: center;
}
.stat-value { font-size: 2rem; font-weight: 700; color: #60a5fa; }
.stat-label { color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 0.3rem; }

/* ── Footer ───────────────────────────────────────── */
.report-footer {
  text-align: center;
  padding: 2rem 0;
  color: #475569;
  font-size: 0.85rem;
  border-top: 1px solid #1e293b;
}

/* ── Print ────────────────────────────────────────── */
@media print {
  body { background: #fff; color: #1a1a1a; max-width: 100%; }
  .report-header, .exec-summary, .finding-card, .stat-card, .endpoints-section details,
  .tech-details { background: #fff; border-color: #ddd; }
  .finding-card[open] .finding-body { display: block; }
  .donut-chart { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  h1, h2, h3, h4, h5 { color: #1a1a1a; }
  .meta-label, .stat-label, .finding-url, .finding-summary { color: #555; }
  .severity-badge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}

/* ── Responsive ───────────────────────────────────── */
@media (max-width: 768px) {
  body { padding: 0.75rem; }
  .summary-grid { grid-template-columns: 1fr; }
  .header-meta { flex-direction: column; gap: 0.5rem; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
  .finding-summary { padding: 0.75rem; }
}
</style>"""
