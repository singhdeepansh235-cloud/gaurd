"""Finding prioritizer for Sentinal-Fuzz.

Sorts enriched findings by a composite priority score so the most
critical, easiest-to-exploit, highest-impact vulnerabilities appear
first in reports and CLI output.

Usage::

    from sentinal_fuzz.analyzer.prioritizer import prioritize

    sorted_findings = prioritize(enriched_findings)
"""

from __future__ import annotations

from sentinal_fuzz.analyzer.classifier import EnrichedFinding
from sentinal_fuzz.core.models import SeverityLevel
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("prioritizer")

# Severity sort order — higher number = higher priority
_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}

# Exploit difficulty sort order — higher number = higher priority (easy first)
_EXPLOIT_ORDER: dict[str, int] = {
    "easy": 3,
    "medium": 2,
    "hard": 1,
}


def _sort_key(finding: EnrichedFinding) -> tuple[int, float, int, str]:
    """Compute a composite sort key for a finding.

    Priority order (all descending except URL which is ascending):
    1. Severity level (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    2. CVSS score (9.8 > 6.1 > 2.0)
    3. Exploit difficulty (easy > medium > hard)
    4. URL (alphabetical — groups same-URL findings together)

    Returns a tuple that, when sorted in descending order for the
    first three fields and ascending for the fourth, produces the
    desired priority.
    """
    severity_rank = _SEVERITY_ORDER.get(finding.severity, 0)
    exploit_rank = _EXPLOIT_ORDER.get(finding.exploit_difficulty, 0)
    return (
        -severity_rank,       # Negate for descending
        -finding.cvss_score,  # Negate for descending
        -exploit_rank,        # Negate for descending
        finding.url,          # Ascending (alphabetical grouping)
    )


def prioritize(
    findings: list[EnrichedFinding],
) -> list[EnrichedFinding]:
    """Sort findings by composite priority.

    Ordering:
    1. Severity (Critical first)
    2. CVSS score (descending)
    3. Exploit difficulty (easy first — easy-to-exploit vulns are most urgent)
    4. URL (alphabetical — groups same-endpoint findings together)

    Args:
        findings: List of enriched findings to sort.

    Returns:
        A new list sorted by priority (highest priority first).
    """
    if not findings:
        return []

    sorted_findings = sorted(findings, key=_sort_key)

    # Log summary
    if sorted_findings:
        top = sorted_findings[0]
        log.info(
            "Top priority: [%s] %s on %s (CVSS %.1f, %s exploit)",
            top.severity.value.upper(), top.title, top.url,
            top.cvss_score, top.exploit_difficulty,
        )

    return sorted_findings
