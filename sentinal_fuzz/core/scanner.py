"""Main scan orchestrator for Sentinal-Fuzz.

The ``Scanner`` class is the top-level entry point that drives the
full DAST pipeline:

    crawl → build_attack_surface → fuzz → analyze → report

Usage::

    from sentinal_fuzz.core.config import ScanConfig
    from sentinal_fuzz.core.scanner import Scanner

    config = ScanConfig(target="https://example.com")
    scanner = Scanner(config=config)
    result = await scanner.run()
    print(f"Found {len(result.findings)} vulnerabilities")
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.event_bus import EventBus
from sentinal_fuzz.core.models import Endpoint, Finding, ScanResult
from sentinal_fuzz.utils.http import HttpClient
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("scanner")

# Type alias for event callbacks (retained for backward compat)
EventCallback = Callable[..., Any]


class Scanner:
    """Main DAST scanner orchestrator.

    Coordinates the crawler, fuzzer, analyzer, and reporter into a
    single scan pipeline. Uses an ``EventBus`` for real-time progress
    updates consumed by the CLI or external integrations.

    The pipeline runs as:
        1. **crawl** — discover endpoints on the target
        2. **build attack surface** — classify inputs
        3. **fuzz** — test endpoints with payloads from templates
        4. **analyze** — deduplicate, score, and validate findings
        5. **report** — generate output in the configured formats

    Attributes:
        config:      Scan configuration.
        event_bus:   Event emitter for real-time scan progress.
        http_client: Shared HTTP client (created during run).
        result:      The scan result (populated after run completes).

    Event bus events:
        - ``url_found``       — kwargs: url (str)
        - ``crawl_complete``  — kwargs: endpoints (list[Endpoint])
        - ``finding``         — kwargs: finding (Finding)
        - ``scan_complete``   — kwargs: result (ScanResult)
        - ``stage_changed``   — kwargs: stage (str)

    Example::

        scanner = Scanner(config=ScanConfig(target="https://example.com"))

        # Register event handlers
        scanner.event_bus.on("url_found", lambda url: print(f"Found: {url}"))
        scanner.event_bus.on("finding", lambda finding: print(f"VULN: {finding.title}"))
        scanner.event_bus.on("scan_complete", lambda result: print(f"Done: {len(result.findings)} findings"))

        result = await scanner.run()
    """

    def __init__(self, config: ScanConfig) -> None:
        """Initialize the scanner with a configuration.

        Args:
            config: Scan configuration specifying target, depth,
                    concurrency, templates, and other options.
        """
        self.config = config
        self.http_client: HttpClient | None = None
        self.result: ScanResult | None = None
        self.start_time: datetime = datetime.now()

        # ── Event bus ─────────────────────────────────────────────
        self.event_bus = EventBus()

        # ── Legacy event hook lists (backward compat) ─────────────
        self.on_url_found: list[EventCallback] = []
        self.on_finding: list[EventCallback] = []
        self.on_scan_complete: list[EventCallback] = []

        # ── Pipeline components (pluggable overrides) ─────────────
        self._crawler: Any = None  # BaseCrawler subclass instance
        self._fuzzer: Any = None   # BaseFuzzer subclass instance
        self._reporters: list[Any] = []  # BaseReporter subclass instances

        log.info(
            "Scanner initialized: target=%s, profile=%s, depth=%d, concurrency=%d",
            config.target, config.scan_profile, config.depth, config.concurrency,
        )

    # ── Helpers ────────────────────────────────────────────────────

    def emit(self, event: str, **kwargs: Any) -> None:
        """Emit an event through the EventBus and legacy callbacks.

        Args:
            event:    Event name.
            **kwargs: Data forwarded to handlers.
        """
        # EventBus (new)
        self.event_bus.emit(event, **kwargs)

        # Legacy hook lists (backward compat)
        if event == "url_found":
            url = kwargs.get("url", "")
            for cb in self.on_url_found:
                try:
                    cb(url)
                except Exception as exc:
                    log.warning("Legacy url_found callback error: %s", exc)
        elif event == "finding":
            finding = kwargs.get("finding")
            for cb in self.on_finding:
                try:
                    cb(finding)
                except Exception as exc:
                    log.warning("Legacy finding callback error: %s", exc)
        elif event == "scan_complete":
            result = kwargs.get("result")
            for cb in self.on_scan_complete:
                try:
                    cb(result)
                except Exception as exc:
                    log.warning("Legacy scan_complete callback error: %s", exc)

    def _build_stats(self) -> dict[str, Any]:
        """Build a stats summary dict for logging."""
        return {
            "total_requests": self.http_client.request_count if self.http_client else 0,
        }

    # ── Main pipeline ─────────────────────────────────────────────

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline.

        This is the main entry point for running a scan. It:
        1. Initializes the HTTP client
        2. Runs the 5 pipeline stages in order
        3. Fires events at appropriate milestones
        4. Returns the complete scan result

        Returns:
            A ``ScanResult`` containing all endpoints and findings.

        Raises:
            ValueError: If the target URL is invalid.
            RuntimeError: If a critical pipeline stage fails.
        """
        self.start_time = datetime.now()
        log.info("Starting scan: %s", self.config.target)
        self.emit("stage_changed", stage="Initializing")

        async with HttpClient(
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            follow_redirects=self.config.follow_redirects,
        ) as client:
            self.http_client = client

            # ── Phase 1: Crawl ────────────────────────────────────
            self.emit("stage_changed", stage="Crawling")
            log.info("[1/5] Crawling target: %s", self.config.target)
            all_endpoints = await self._phase_crawl()
            self.emit("crawl_complete", endpoints=all_endpoints)
            log.info("Crawl complete: %d endpoints discovered", len(all_endpoints))

            # ── Phase 2: Build attack surface ─────────────────────
            self.emit("stage_changed", stage="Classifying")
            log.info("[2/5] Building attack surface...")
            classified = self._phase_classify(all_endpoints)
            log.info("Classification complete: %d endpoints classified", len(classified))

            # ── Phase 3: Fuzz ─────────────────────────────────────
            self.emit("stage_changed", stage="Fuzzing")
            log.info("[3/5] Fuzzing %d endpoints...", len(all_endpoints))
            all_findings = await self._phase_fuzz(all_endpoints, classified)
            log.info("Fuzzing complete: %d raw findings", len(all_findings))

            # ── Phase 4: Analyze ──────────────────────────────────
            self.emit("stage_changed", stage="Analyzing")
            log.info("[4/5] Analyzing findings...")
            enriched = self._phase_analyze(all_findings)
            log.info("Analysis complete: %d validated findings", len(enriched))

            # ── Phase 5: Report ───────────────────────────────────
            self.emit("stage_changed", stage="Reporting")
            log.info("[5/5] Generating reports...")
            result = ScanResult(
                target=self.config.target,
                start_time=self.start_time,
                end_time=datetime.now(),
                endpoints=all_endpoints,
                findings=enriched,
                scan_profile=self.config.scan_profile,
            )

            # Update stats
            result.stats.total_requests = client.request_count
            result.stats.urls_crawled = len(all_endpoints)
            result.stats.endpoints_found = len(all_endpoints)
            duration = max(result.duration_seconds, 0.001)
            result.stats.requests_per_second = result.stats.total_requests / duration

            # Severity counts
            for finding in enriched:
                sev_key = finding.severity.value
                result.stats.findings_by_severity[sev_key] = (
                    result.stats.findings_by_severity.get(sev_key, 0) + 1
                )

            self._phase_report(result)

        # ── Finalize ──────────────────────────────────────────────
        self.result = result
        self.emit("stage_changed", stage="Complete ✓")
        self.emit("scan_complete", result=result)

        log.info(
            "Scan complete in %.1fs: %d endpoints, %d findings (%d critical, %d high)",
            result.duration_seconds,
            len(result.endpoints),
            len(result.findings),
            result.critical_count,
            result.high_count,
        )

        return result

    # ── Phase implementations ─────────────────────────────────────

    async def _phase_crawl(self) -> list[Endpoint]:
        """Phase 1: Discover endpoints on the target.

        Uses the registered crawler (or the factory default) plus
        a lightweight API discovery pass.
        """
        assert self.http_client is not None

        # Use registered crawler, or factory default
        if self._crawler is not None:
            crawler = self._crawler
        else:
            from sentinal_fuzz.crawler.crawler_factory import get_crawler
            crawler = get_crawler(self.config, self.http_client)

        try:
            endpoints = await crawler.crawl(self.config.target)
        except Exception as exc:
            log.error("Crawler failed: %s", exc)
            # Fallback: create a single endpoint for the target
            endpoints = [Endpoint(url=self.config.target, method="GET", source="initial")]

        # Notify per URL
        for ep in endpoints:
            self.emit("url_found", url=ep.url)

        # Deduplicate endpoints
        seen: set[tuple[str, str]] = set()
        unique: list[Endpoint] = []
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        return unique

    def _phase_classify(
        self, endpoints: list[Endpoint],
    ) -> dict[int, list[str]]:
        """Phase 2: Classify endpoints into vulnerability tags.

        Uses InputClassifier to determine which vulnerability classes
        each endpoint's parameters are susceptible to.

        Returns:
            Mapping of endpoint index → list of vulnerability tags.
        """
        from sentinal_fuzz.fuzzer.input_classifier import InputClassifier

        classifier = InputClassifier()
        classified: dict[int, list[str]] = {}

        for idx, endpoint in enumerate(endpoints):
            param_tags = classifier.classify(endpoint)
            # Merge all parameter tags into a single list for this endpoint
            all_tags: list[str] = []
            for tags in param_tags.values():
                all_tags.extend(tags)
            # Deduplicate
            seen: set[str] = set()
            unique_tags: list[str] = []
            for tag in all_tags:
                if tag not in seen:
                    seen.add(tag)
                    unique_tags.append(tag)
            classified[idx] = unique_tags

        return classified

    async def _phase_fuzz(
        self,
        endpoints: list[Endpoint],
        classified: dict[int, list[str]],
    ) -> list[Finding]:
        """Phase 3: Fuzz all endpoints with applicable templates.

        For each endpoint, loads templates that match the classified
        tags and runs the FuzzEngine against them.
        """
        assert self.http_client is not None

        # If a custom fuzzer is registered, use it instead
        if self._fuzzer is not None:
            findings = await self._fuzzer.fuzz_all(endpoints)
            for f in findings:
                self.emit("finding", finding=f)
            return findings

        from sentinal_fuzz.fuzzer.engine import FuzzEngine
        from sentinal_fuzz.fuzzer.template_loader import TemplateLoader

        engine = FuzzEngine(http_client=self.http_client, config=self.config)
        loader = TemplateLoader()
        all_findings: list[Finding] = []
        total_endpoints = len(endpoints)

        for idx, endpoint in enumerate(endpoints):
            tags = classified.get(idx, [])

            # Emit progress: starting this endpoint
            self.emit("fuzz_progress", endpoints_tested=idx,
                      endpoints_total=total_endpoints,
                      requests_sent=self.http_client.request_count,
                      current_url=endpoint.url)

            # Load templates matching this endpoint's tags
            if tags:
                try:
                    templates = loader.load_by_tags(tags)
                except Exception as exc:
                    log.warning("Failed to load templates for tags %s: %s", tags, exc)
                    templates = []
            else:
                # No specific tags — load all templates
                try:
                    templates = loader.load_all()
                except Exception as exc:
                    log.warning("Failed to load templates: %s", exc)
                    templates = []

            if not templates:
                log.debug("No templates for endpoint %s", endpoint.url)
                continue

            try:
                findings = await engine.fuzz_endpoint(endpoint, templates)
            except Exception as exc:
                log.warning("Fuzz error on %s: %s", endpoint.url, exc)
                findings = []

            for f in findings:
                self.emit("finding", finding=f)
                all_findings.append(f)

            # Emit progress: finished this endpoint
            self.emit("fuzz_progress", endpoints_tested=idx + 1,
                      endpoints_total=total_endpoints,
                      requests_sent=self.http_client.request_count,
                      current_url=endpoint.url)

        return all_findings

    def _phase_analyze(self, findings: list[Finding]) -> list[Finding]:
        """Phase 4: Deduplicate, classify, and prioritize findings.

        Runs the VulnClassifier to enrich findings with CVSS/CWE data,
        then deduplicates and sorts by priority.

        Returns findings as ``Finding`` objects (not EnrichedFinding)
        to keep ScanResult compatible.
        """
        if not findings:
            return []

        from sentinal_fuzz.analyzer.classifier import VulnClassifier
        from sentinal_fuzz.fuzzer.deduplicator import deduplicate

        # Step 1: Deduplicate
        deduped = deduplicate(findings)

        # Step 2: Enrich with VulnClassifier (updates CWE/OWASP/remediation)
        classifier = VulnClassifier()
        for finding in deduped:
            enriched = classifier.classify(finding)
            # Copy enrichment data back into the Finding
            if not finding.cwe and enriched.cwe:
                finding.cwe = enriched.cwe
            if not finding.owasp and enriched.owasp:
                finding.owasp = enriched.owasp
            if not finding.remediation and enriched.remediation:
                finding.remediation = enriched.remediation

        # Step 3: Sort by severity (critical first)
        severity_order = {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
        }
        deduped.sort(
            key=lambda f: (
                -severity_order.get(f.severity.value, 0),
                -f.confidence,
            ),
        )

        return deduped

    def _phase_report(self, result: ScanResult) -> None:
        """Phase 5: Generate reports in configured formats.

        Uses registered reporters, or falls back to the factory.
        """
        reporters = self._reporters

        if not reporters:
            try:
                from sentinal_fuzz.reporter.reporter_factory import get_reporter
                factory_result = get_reporter(
                    self.config.output_format,
                    output_dir=self.config.output_dir,
                )
                if isinstance(factory_result, list):
                    reporters = factory_result
                else:
                    reporters = [factory_result]
            except Exception as exc:
                log.warning("Could not create reporters: %s", exc)
                reporters = []

        for reporter in reporters:
            try:
                filepath = reporter.generate(result)
                log.info("Report generated: %s", filepath)
            except Exception as exc:
                log.error(
                    "Report generation failed (%s): %s",
                    getattr(reporter, "format_name", "unknown"),
                    exc,
                )

        if not reporters:
            self._print_summary(result)

    # ── Plugin registration ───────────────────────────────────────

    def set_crawler(self, crawler: Any) -> None:
        """Register a custom crawler implementation.

        Args:
            crawler: An instance of a ``BaseCrawler`` subclass.
        """
        self._crawler = crawler
        log.debug("Crawler registered: %s", type(crawler).__name__)

    def set_fuzzer(self, fuzzer: Any) -> None:
        """Register a custom fuzzer implementation.

        Args:
            fuzzer: An instance of a ``BaseFuzzer`` subclass.
        """
        self._fuzzer = fuzzer
        log.debug("Fuzzer registered: %s", type(fuzzer).__name__)

    def add_reporter(self, reporter: Any) -> None:
        """Register a report generator.

        Multiple reporters can be registered; all will be executed.

        Args:
            reporter: An instance of a ``BaseReporter`` subclass.
        """
        self._reporters.append(reporter)
        log.debug("Reporter registered: %s", type(reporter).__name__)

    # ── Internal helpers ──────────────────────────────────────────

    @staticmethod
    def _print_summary(result: ScanResult) -> None:
        """Print a brief scan summary to the console."""
        print()
        print("=" * 60)
        print("  Sentinal-Fuzz Scan Summary")
        print("=" * 60)
        print(f"  Target:     {result.target}")
        print(f"  Duration:   {result.duration_seconds:.1f}s")
        print(f"  Endpoints:  {len(result.endpoints)}")
        print(f"  Findings:   {len(result.findings)}")
        if result.findings:
            print(f"  Critical:   {result.critical_count}")
            print(f"  High:       {result.high_count}")
        print("=" * 60)
        print()
