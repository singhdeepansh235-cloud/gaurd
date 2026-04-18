"""Shared scoring helpers for scan findings and phishing signals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


_SCAN_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 5,
    "low": 2,
    "info": 0,
}


def calculate_scan_risk_score(findings: Iterable[Any]) -> int:
    """Calculate the existing scan risk score from finding severities."""
    risk = 0
    for finding in findings:
        severity = _extract_severity(finding)
        risk += _SCAN_SEVERITY_WEIGHTS.get(severity, 0)
    return min(risk, 100)


def calculate_phishing_risk_score(weights: Iterable[int]) -> int:
    """Calculate a capped risk score for phishing signals."""
    return min(sum(weights), 100)


def phishing_status_from_score(risk_score: int) -> str:
    """Map a phishing risk score to a user-facing status label."""
    if risk_score >= 60:
        return "Likely Phishing"
    if risk_score >= 25:
        return "Suspicious"
    return "Safe"


def _extract_severity(finding: Any) -> str:
    """Support both dataclass findings and serialized finding dicts."""
    if hasattr(finding, "severity"):
        severity = getattr(finding, "severity")
        if hasattr(severity, "value"):
            return str(severity.value)
        return str(severity)

    if isinstance(finding, Mapping):
        return str(finding.get("severity", "info"))

    return "info"
