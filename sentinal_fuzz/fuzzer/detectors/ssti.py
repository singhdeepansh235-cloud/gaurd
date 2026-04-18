"""SSTI (Server-Side Template Injection) detector for Sentinal-Fuzz.

Uses math-based probe expressions to detect template engines that
evaluate user input. Each probe produces a unique numeric result
that is unlikely to appear in normal responses.

Supported engines:
    - Jinja2 / Twig:  ``{{7*7}}``  -> ``49``
    - Freemarker:      ``${7*7}``  -> ``49``
    - Pebble:          ``#{7*7}``  -> ``49``
    - ERB / JSP:       ``<%= 7*7 %>`` -> ``49``
    - Jinja2 advanced: ``{{7*'7'}}`` -> ``7777777`` (string repeat)

Usage::

    detector = SSTIDetector()
    probes = detector.get_probes()
    for probe in probes:
        # inject probe.payload, check response for probe.expected
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    pass

log = get_logger("detector.ssti")


@dataclass(frozen=True)
class SSTIProbe:
    """A single SSTI detection probe.

    Attributes:
        payload:  The template expression to inject.
        expected: The evaluated result to look for.
        engine:   Name of the template engine this targets.
    """

    payload: str
    expected: str
    engine: str


# ── Probe definitions ──────────────────────────────────────────────
_PROBES: list[SSTIProbe] = [
    SSTIProbe(payload="{{7*7}}", expected="49", engine="Jinja2/Twig"),
    SSTIProbe(payload="{{7*'7'}}", expected="7777777", engine="Jinja2"),
    SSTIProbe(payload="${7*7}", expected="49", engine="Freemarker/Groovy"),
    SSTIProbe(payload="#{7*7}", expected="49", engine="Pebble/Thymeleaf"),
    SSTIProbe(payload="<%= 7*7 %>", expected="49", engine="ERB/JSP"),
    SSTIProbe(payload="${{7*191}}", expected="1337", engine="Jinja2/Twig (alt)"),
    SSTIProbe(payload="{{191*7}}", expected="1337", engine="Jinja2/Twig (alt2)"),
]

# ── Template engine error patterns ─────────────────────────────────
_ENGINE_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"jinja2\.exceptions", "Jinja2"),
    (r"UndefinedError", "Jinja2"),
    (r"TemplateSyntaxError.*?jinja", "Jinja2"),
    (r"Twig_Error_Syntax|Twig\\Error\\SyntaxError", "Twig"),
    (r"FreeMarkerException|freemarker\.core\.", "Freemarker"),
    (r"org\.apache\.velocity|VelocityException", "Velocity"),
    (r"com\.mitchellbosecke\.pebble|PebbleException", "Pebble"),
    (r"org\.thymeleaf\.exceptions|TemplateProcessingException", "Thymeleaf"),
]


class SSTIDetector:
    """Detect Server-Side Template Injection vulnerabilities.

    Injects math-based probes and checks if the evaluated result
    appears in the response. Also scans for template engine error
    messages that confirm server-side evaluation.
    """

    @staticmethod
    def get_probes() -> list[SSTIProbe]:
        """Return all SSTI detection probes."""
        return list(_PROBES)

    @staticmethod
    def get_payloads() -> list[str]:
        """Return just the payload strings for injection."""
        return [p.payload for p in _PROBES]

    @staticmethod
    def check_probe(
        probe: SSTIProbe,
        response_text: str,
        baseline_text: str,
    ) -> bool:
        """Check if a probe's expected result appears in the response.

        Only returns True if the expected value is in the fuzzed
        response but NOT in the baseline (to avoid false positives
        from pages that naturally contain "49").
        """
        expected = probe.expected
        # Must be in fuzzed response
        if expected not in response_text:
            return False
        # Must NOT be in baseline (or at least appear more times)
        fuzzed_count = response_text.count(expected)
        baseline_count = baseline_text.count(expected)
        return fuzzed_count > baseline_count

    @staticmethod
    def detect_engine_errors(response_text: str) -> list[tuple[str, str]]:
        """Scan response for template engine error messages.

        Returns:
            List of ``(pattern, engine_name)`` tuples for each match.
        """
        found: list[tuple[str, str]] = []
        for pattern, engine in _ENGINE_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                found.append((pattern, engine))
        return found

    @staticmethod
    def create_finding(
        url: str,
        parameter: str,
        payload: str,
        engine: str,
        evidence: str,
    ) -> Finding:
        """Build an SSTI Finding."""
        return Finding(
            title=f"Server-Side Template Injection ({engine})",
            severity=SeverityLevel.CRITICAL,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence[:200],
            cwe="CWE-94",
            owasp="A03:2021-Injection",
            remediation=(
                "Never pass user input directly into template rendering. "
                "Use a sandboxed template engine and avoid user-controlled "
                "template strings entirely. Validate that input does not "
                "contain template syntax characters."
            ),
            confidence=0.9,
            template_id="ssti-detector",
        )
