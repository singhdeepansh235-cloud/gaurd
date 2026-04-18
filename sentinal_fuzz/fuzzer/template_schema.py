"""Data model for Sentinal-Fuzz YAML fuzzing templates.

Defines the complete schema that every template file must conform to.
Templates describe WHAT to test (payloads) and HOW to detect a hit
(matchers). The ``TemplateLoader`` reads YAML files into these
dataclasses; the ``TemplateValidator`` verifies correctness.

Usage::

    from sentinal_fuzz.fuzzer.template_schema import FuzzTemplate, Matcher

    template = FuzzTemplate(
        id="xss-reflected",
        name="Reflected XSS",
        severity=SeverityLevel.HIGH,
        tags=["xss", "injection"],
        description="Detects reflected XSS",
        payloads=["<script>alert(1)</script>"],
        matchers=[
            Matcher(type="word", part="body", words=["<script>alert(1)</script>"]),
        ],
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinal_fuzz.core.models import SeverityLevel


# ── Valid enum-like constants ──────────────────────────────────────
VALID_MATCHER_TYPES = frozenset({"word", "regex", "status", "timing", "size", "header"})
VALID_MATCHER_PARTS = frozenset({"body", "header", "status", "response_time", "all"})
VALID_TARGET_PARAMS = frozenset({"query", "form", "header", "cookie", "path", "json"})
VALID_CONDITIONS = frozenset({"or", "and"})


@dataclass
class Matcher:
    """A single matching rule applied to the HTTP response.

    Matchers inspect a specific *part* of the response (body, headers,
    status code, response time) looking for indicators of a vulnerability.

    Attributes:
        type:         Match strategy — ``word`` (exact substring), ``regex``,
                      ``status`` (HTTP code), ``timing`` (response time),
                      ``size`` (response length), ``header`` (header value).
        part:         Which part of the response to inspect.
        words:        Exact strings to search for (type=word).
        regex:        Regular expression patterns (type=regex).
        status:       HTTP status codes to match (type=status).
        headers:      Header name→value mappings to check (type=header).
        condition:    How to combine multiple words/regex in *this* matcher:
                      ``or`` = any match triggers, ``and`` = all must match.
        negative:     If True, the matcher succeeds when the pattern is
                      **not** found. Useful for checking the *absence* of a
                      protective header.
        threshold_ms: For type=timing — response is suspicious if elapsed
                      time exceeds this value in milliseconds.
        size_min:     For type=size — minimum response body length.
        size_max:     For type=size — maximum response body length.
    """

    type: str = "word"
    part: str = "body"
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    condition: str = "or"
    negative: bool = False
    threshold_ms: int = 0
    size_min: int = 0
    size_max: int = 0


@dataclass
class FuzzTemplate:
    """Complete definition of a fuzzing test case.

    A template is the fundamental unit of scanning in Sentinal-Fuzz.
    It combines a set of payloads to inject with matchers that
    detect vulnerability indicators in the HTTP response.

    Attributes:
        id:                 Unique slug identifier (e.g. ``xss-reflected``).
        name:               Human-readable title for reports.
        severity:           Severity rating for findings produced by this template.
        tags:               Classification tags for filtering (e.g. ``["xss", "owasp-a03"]``).
        description:        What this template tests and why it matters.
        references:         URLs to relevant documentation / advisories.
        target_params:      Which input vectors to inject into
                            (query, form, header, cookie, path, json).
        payloads:           Inline list of payload strings **or** a file path
                            (``str``) pointing to a newline-delimited payload file.
        matchers:           List of matchers that detect a vulnerability hit.
        matchers_condition: How to combine multiple matchers: ``or`` (any matcher
                            triggers a finding) or ``and`` (all must match).
        stop_on_first_match: If True, stop testing this template against this
                             endpoint after the first confirmed finding.
        cwe:                CWE identifier (e.g. ``CWE-79``).
        owasp:              OWASP Top 10 mapping (e.g. ``A03:2021-Injection``).
        remediation:        Suggested fix text included in findings.
    """

    id: str
    name: str
    severity: SeverityLevel
    tags: list[str] = field(default_factory=list)
    description: str = ""
    references: list[str] = field(default_factory=list)
    target_params: list[str] = field(default_factory=lambda: ["query", "form"])
    payloads: list[str] | str = field(default_factory=list)
    matchers: list[Matcher] = field(default_factory=list)
    matchers_condition: str = "or"
    stop_on_first_match: bool = True
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""

    @property
    def payload_list(self) -> list[str]:
        """Return payloads as a flat list (resolving file references).

        If ``payloads`` is a string it is treated as a file path indicator.
        The actual file loading is handled by ``TemplateLoader`` before
        this property is typically accessed, so by runtime this should
        always be a list.
        """
        if isinstance(self.payloads, list):
            return self.payloads
        return []

    @property
    def is_passive(self) -> bool:
        """Return True if this template needs no payloads (passive check).

        Passive templates only inspect existing responses without injecting
        anything — e.g. security-header checks, sensitive-data scanning.
        """
        return len(self.payload_list) == 0 and isinstance(self.payloads, list)
