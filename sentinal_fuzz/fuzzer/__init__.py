"""Fuzzer module — template-based fuzzing and payload injection."""

from sentinal_fuzz.fuzzer.base import BaseFuzzer, FuzzStats
from sentinal_fuzz.fuzzer.deduplicator import deduplicate
from sentinal_fuzz.fuzzer.engine import FuzzEngine, InjectionPoint
from sentinal_fuzz.fuzzer.false_positive_filter import FalsePositiveFilter
from sentinal_fuzz.fuzzer.input_classifier import (
    ClassificationMetrics,
    InputClassifier,
)
from sentinal_fuzz.fuzzer.remediations import REMEDIATION_MAP
from sentinal_fuzz.fuzzer.template_loader import TemplateLoader, TemplateLoadError
from sentinal_fuzz.fuzzer.template_schema import FuzzTemplate, Matcher
from sentinal_fuzz.fuzzer.template_validator import validate as validate_template

__all__ = [
    "REMEDIATION_MAP",
    "BaseFuzzer",
    "ClassificationMetrics",
    "FalsePositiveFilter",
    "FuzzEngine",
    "FuzzStats",
    "FuzzTemplate",
    "InputClassifier",
    "InjectionPoint",
    "Matcher",
    "TemplateLoadError",
    "TemplateLoader",
    "deduplicate",
    "validate_template",
]
