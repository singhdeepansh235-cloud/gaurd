"""Phishing detection helpers for suspicious domain analysis."""

from sentinal_fuzz.phishing_detection.detector import (
    PhishingCheckResult,
    analyze_phishing_target,
    extract_domain,
)

__all__ = [
    "PhishingCheckResult",
    "analyze_phishing_target",
    "extract_domain",
]
