"""SARIF 2.1.0 report generator for Sentinal-Fuzz.

Produces a SARIF (Static Analysis Results Interchange Format) report
compatible with GitHub Code Scanning, Azure DevOps, and other CI/CD
platforms that consume SARIF.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Usage::

    from sentinal_fuzz.reporter.sarif_reporter import SarifReporter

    reporter = SarifReporter(output_dir="reports")
    filepath = reporter.generate(scan_result)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sentinal_fuzz.core.models import Finding, ScanResult, SeverityLevel
from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("sarif_reporter")

# SARIF severity mapping
_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.INFO: "note",
}

_LEVEL_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.INFO: "none",
}

# SARIF security-severity mapping (numeric)
_SECURITY_SEVERITY: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "9.5",
    SeverityLevel.HIGH: "8.0",
    SeverityLevel.MEDIUM: "5.5",
    SeverityLevel.LOW: "3.0",
    SeverityLevel.INFO: "0.0",
}


@dataclass
class SarifReporter(BaseReporter):
    """Generate a SARIF 2.1.0 report for CI/CD integration."""

    @property
    def file_extension(self) -> str:
        return ".sarif"

    @property
    def format_name(self) -> str:
        return "SARIF"

    def generate(self, result: ScanResult) -> str:
        """Generate the SARIF report and write to disk.

        Args:
            result: The complete scan result.

        Returns:
            Absolute file path of the generated SARIF report.
        """
        sarif = self.build_sarif(result)
        content = json.dumps(sarif, indent=2, ensure_ascii=False, default=str)
        filename = self._build_filename(result)
        filepath = self._write_file(filename, content)
        log.info("SARIF report generated: %s", filepath)
        return filepath

    @staticmethod
    def build_sarif(result: ScanResult) -> dict[str, Any]:
        """Build the SARIF 2.1.0 document structure.

        Args:
            result: The scan result to convert.

        Returns:
            A SARIF-compliant dictionary.
        """
        # Build unique rules from findings
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in result.findings:
            rule_id = finding.template_id or finding.cwe or finding.id
            if rule_id not in rules:
                rules[rule_id] = _build_rule(finding, rule_id)
            results.append(_build_result(finding, rule_id))

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinal-Fuzz",
                            "version": result.scanner_version,
                            "semanticVersion": result.scanner_version,
                            "informationUri": "https://github.com/sentinal-fuzz/sentinal-fuzz",
                            "rules": list(rules.values()),
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": result.start_time.isoformat() + "Z",
                            "endTimeUtc": (
                                result.end_time.isoformat() + "Z"
                                if result.end_time
                                else None
                            ),
                            "properties": {
                                "scan_id": result.scan_id,
                                "scan_profile": result.scan_profile,
                                "target": result.target,
                            },
                        },
                    ],
                },
            ],
        }


def _build_rule(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a finding."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {
            "text": finding.remediation or f"Vulnerability: {finding.title}",
        },
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html"
        if finding.cwe
        else "https://owasp.org",
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(
                finding.severity, "0.0"
            ),
            "tags": ["security"],
        },
    }
    if finding.cwe:
        rule["properties"]["tags"].append(finding.cwe)
    if finding.owasp:
        rule["properties"]["tags"].append(finding.owasp)
    return rule


def _build_result(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF result entry from a finding."""
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL_MAP.get(finding.severity, "note"),
        "message": {
            "text": (
                f"{finding.title} found at {finding.url}"
                + (f" (parameter: {finding.parameter})" if finding.parameter else "")
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.url,
                        "uriBaseId": "%SRCROOT%",
                    },
                },
                "properties": {},
            },
        ],
    }

    if finding.parameter:
        result["locations"][0]["properties"]["parameter"] = finding.parameter

    # Partial fingerprint for deduplication
    result["partialFingerprints"] = {
        "primaryLocationLineHash": f"{finding.url}:{finding.parameter}:{finding.cwe}",
    }

    # Fix information
    if finding.remediation:
        result["fixes"] = [
            {
                "description": {"text": finding.remediation},
            },
        ]

    return result
