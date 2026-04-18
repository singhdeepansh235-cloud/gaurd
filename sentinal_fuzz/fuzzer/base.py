"""Abstract base fuzzer for Sentinal-Fuzz.

All fuzzer implementations (template-based fuzzer, raw payload fuzzer,
auth-testing fuzzer) extend ``BaseFuzzer`` and implement the
``fuzz()`` coroutine.

Usage::

    class TemplateFuzzer(BaseFuzzer):
        async def fuzz(self, endpoint: Endpoint) -> list[Finding]:
            ...

    fuzzer = TemplateFuzzer(config=scan_config, http_client=client)
    findings = await fuzzer.fuzz(endpoint)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinal_fuzz.core.models import Endpoint, Finding
from sentinal_fuzz.utils.logger import get_logger

if TYPE_CHECKING:
    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.utils.http import HttpClient

log = get_logger("fuzzer")


@dataclass
class FuzzStats:
    """Statistics tracked during a fuzzing session.

    Attributes:
        payloads_sent:    Total number of payloads sent.
        findings_count:   Total number of findings produced.
        errors:           Number of request errors encountered.
        endpoints_tested: Number of endpoints fuzzed.
        templates_used:   Set of template IDs that were executed.
    """

    payloads_sent: int = 0
    findings_count: int = 0
    errors: int = 0
    endpoints_tested: int = 0
    templates_used: set[str] = field(default_factory=set)


class BaseFuzzer(abc.ABC):
    """Abstract base class for all fuzzers.

    Subclasses must implement:
        - ``fuzz(endpoint) -> list[Finding]``: Test an endpoint for vulnerabilities.

    Optionally override:
        - ``load_templates()``: Load fuzzing templates from disk.
        - ``should_skip(endpoint)``: Logic to skip certain endpoints.
        - ``post_process(findings)``: Filter/deduplicate findings.

    Attributes:
        config:      The scan configuration.
        http_client: Shared HTTP client instance.
        stats:       Fuzzing statistics tracker.
    """

    def __init__(
        self,
        config: ScanConfig,
        http_client: HttpClient,
    ) -> None:
        self.config = config
        self.http_client = http_client
        self.stats = FuzzStats()
        self._on_finding_callbacks: list[callable] = []  # type: ignore[type-arg]

    def on_finding(self, callback: callable) -> None:  # type: ignore[type-arg]
        """Register a callback to be invoked when a finding is discovered.

        Args:
            callback: A callable that receives a ``Finding`` object.
        """
        self._on_finding_callbacks.append(callback)

    def _notify_finding(self, finding: Finding) -> None:
        """Fire all registered on_finding callbacks."""
        for cb in self._on_finding_callbacks:
            try:
                cb(finding)
            except Exception as exc:
                log.warning("on_finding callback error: %s", exc)

    @abc.abstractmethod
    async def fuzz(self, endpoint: Endpoint) -> list[Finding]:
        """Test a single endpoint for vulnerabilities.

        Implementations should:
        1. Select relevant templates/payloads for this endpoint
        2. Send fuzzed requests to the target
        3. Analyze responses for vulnerability indicators
        4. Return confirmed/suspected findings

        Args:
            endpoint: The discovered endpoint to test.

        Returns:
            A list of ``Finding`` objects for any detected vulnerabilities.
        """
        ...

    async def fuzz_all(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Fuzz multiple endpoints and collect all findings.

        This is a convenience method that iterates over all endpoints,
        calls ``fuzz()`` on each, and aggregates the results. Subclasses
        may override this for parallel execution.

        Args:
            endpoints: List of endpoints to fuzz.

        Returns:
            Aggregated list of all findings.
        """
        all_findings: list[Finding] = []

        for endpoint in endpoints:
            if self.should_skip(endpoint):
                log.debug("Skipping endpoint: %s %s", endpoint.method, endpoint.url)
                continue

            try:
                findings = await self.fuzz(endpoint)
                self.stats.endpoints_tested += 1

                for finding in findings:
                    self._notify_finding(finding)
                    all_findings.append(finding)

                self.stats.findings_count += len(findings)
            except Exception as exc:
                self.stats.errors += 1
                log.error("Fuzzing error on %s: %s", endpoint.url, exc)

        return self.post_process(all_findings)

    def should_skip(self, endpoint: Endpoint) -> bool:
        """Determine whether an endpoint should be skipped during fuzzing.

        Override this for custom skip logic (e.g., skip static assets,
        logout pages, or endpoints without injectable parameters).

        Args:
            endpoint: The endpoint to evaluate.

        Returns:
            True if the endpoint should be skipped.
        """
        # Skip endpoints with no injectable parameters
        if not endpoint.injectable_params:
            return True

        # Skip common static asset paths
        static_extensions = {".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".ttf"}
        from urllib.parse import urlparse
        path = urlparse(endpoint.url).path.lower()
        return any(path.endswith(ext) for ext in static_extensions)

    def post_process(self, findings: list[Finding]) -> list[Finding]:
        """Post-process findings to remove duplicates and false positives.

        Override this for custom deduplication or false-positive filtering.

        Args:
            findings: Raw findings list.

        Returns:
            Deduplicated and filtered findings.
        """
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (finding.url, finding.parameter, finding.cwe)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
