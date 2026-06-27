"""Analyzer module — vulnerability classification, prioritization, and aggregation."""

from sentinal_fuzz.analyzer.aggregator import AnalysisReport, aggregate
from sentinal_fuzz.analyzer.classifier import (
    VULN_KNOWLEDGE_BASE,
    EnrichedFinding,
    VulnClassifier,
)
from sentinal_fuzz.analyzer.prioritizer import prioritize
from sentinal_fuzz.analyzer.response import (
    ERROR_SIGNATURES,
    MatchResult,
    ResponseAnalyzer,
)

__all__ = [
    "ERROR_SIGNATURES",
    "VULN_KNOWLEDGE_BASE",
    "AnalysisReport",
    "EnrichedFinding",
    "MatchResult",
    "ResponseAnalyzer",
    "VulnClassifier",
    "aggregate",
    "prioritize",
]
