"""Remediation guidance map for Sentinal-Fuzz templates.

Maps every known template ``id`` to a plain-English remediation string
that is embedded into ``Finding.remediation``.  The engine falls back
to the template's own ``remediation`` field when a key is missing here.

Usage::

    from sentinal_fuzz.fuzzer.remediations import REMEDIATION_MAP

    fix = REMEDIATION_MAP.get(template.id, template.remediation)
"""

from __future__ import annotations

REMEDIATION_MAP: dict[str, str] = {
    # ── XSS ────────────────────────────────────────────────────────
    "xss-reflected": (
        "Escape all user input before rendering it in HTML. Use your "
        "framework's built-in escaping functions (e.g. Jinja2 autoescape, "
        "React JSX). Never use innerHTML or dangerouslySetInnerHTML with "
        "user data. Implement a strict Content-Security-Policy header to "
        "mitigate impact even if a payload slips through."
    ),
    # ── SQL Injection ──────────────────────────────────────────────
    "sqli-error": (
        "Use parameterised queries (prepared statements) for all database "
        "access. Never concatenate user input into SQL strings. Apply "
        "least-privilege database accounts and disable verbose error "
        "messages in production."
    ),
    "sqli-time": (
        "Use parameterised queries (prepared statements) for all database "
        "access. Never concatenate user input into SQL strings. Apply "
        "query timeouts and connection pool limits to reduce the blast "
        "radius of blind-injection attacks."
    ),
    # ── Path Traversal / LFI ───────────────────────────────────────
    "path-traversal": (
        "Validate and sanitise file path input. Use an allow-list of "
        "permitted file names or paths. Resolve symbolic links and "
        "ensure the canonical path stays within the intended directory. "
        "Run the application with least-privilege filesystem permissions."
    ),
    # ── SSTI ───────────────────────────────────────────────────────
    "ssti-basic": (
        "Never pass user input directly into template rendering. Use a "
        "sandboxed template engine (e.g. Jinja2 SandboxedEnvironment) "
        "and avoid user-controlled template strings entirely. Validate "
        "that input does not contain template syntax characters."
    ),
    # ── SSRF ───────────────────────────────────────────────────────
    "ssrf-basic": (
        "Validate and whitelist destination URLs on the server side. "
        "Block requests to private/internal IP ranges (10.x, 172.16-31.x, "
        "192.168.x) and cloud metadata endpoints (169.254.169.254). Use "
        "DNS resolution checks to prevent DNS-rebinding attacks."
    ),
    # ── Open Redirect ──────────────────────────────────────────────
    "open-redirect": (
        "Validate redirect targets against a whitelist of allowed domains "
        "and paths. Avoid using user-supplied values in Location headers "
        "or meta-refresh tags. If a redirect parameter is necessary, map "
        "it through an enum rather than accepting raw URLs."
    ),
    # ── Security Headers (passive) ─────────────────────────────────
    "security-headers": (
        "Configure the web server or application framework to include "
        "the following response headers: Content-Security-Policy, "
        "Strict-Transport-Security (with includeSubDomains and a long "
        "max-age), X-Frame-Options (DENY or SAMEORIGIN), "
        "X-Content-Type-Options (nosniff), Referrer-Policy, and "
        "Permissions-Policy."
    ),
    # ── Sensitive Data Exposure (passive) ──────────────────────────
    "sensitive-exposure": (
        "Remove API keys, secrets, and tokens from response bodies. "
        "Disable debug mode and verbose error pages in production. "
        "Scrub internal IP addresses and stack traces from all error "
        "responses. Rotate any credentials that may have been exposed."
    ),
}
