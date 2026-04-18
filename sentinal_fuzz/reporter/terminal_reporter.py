"""Rich terminal reporter for Sentinal-Fuzz.

Prints a beautifully formatted scan summary directly to the terminal
using the Rich library with color-coded severity cells, tables, and
panels.

Usage::

    from sentinal_fuzz.reporter.terminal_reporter import TerminalReporter

    reporter = TerminalReporter(verbose=True)
    reporter.generate(scan_result)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinal_fuzz.core.models import Finding, ScanResult, SeverityLevel
from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("terminal_reporter")


# ── Severity → Rich markup ────────────────────────────────────────

_SEV_STYLE: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold white on dark_orange",
    "medium": "bold black on yellow",
    "low": "bold white on blue",
    "info": "dim",
}


@dataclass
class TerminalReporter(BaseReporter):
    """Print a rich terminal summary of scan results.

    This reporter does not write a file — it outputs directly to
    stdout using Rich tables and panels.

    Attributes:
        verbose: If True, show full remediation text and evidence.
    """

    verbose: bool = False

    @property
    def file_extension(self) -> str:
        return ".txt"

    @property
    def format_name(self) -> str:
        return "Terminal"

    def generate(self, result: ScanResult) -> str:
        """Print the scan summary to the terminal.

        Args:
            result: The complete scan result.

        Returns:
            Empty string (no file written — output is printed).
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text

            console = Console()
            self._print_report(console, result)
        except ImportError:
            # Fallback if Rich is not installed
            self._print_fallback(result)
        return ""

    def _print_report(self, console: Any, result: ScanResult) -> None:
        """Render the full report using Rich."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        # ── Header panel ──────────────────────────────────────────
        header = Text()
        header.append("🛡️  Sentinal-Fuzz", style="bold cyan")
        header.append(" — Security Scan Report\n\n", style="dim")
        header.append(f"  Target:   {result.target}\n")
        header.append(f"  Duration: {result.duration_seconds:.1f}s\n")
        header.append(f"  Profile:  {result.scan_profile}\n")
        header.append(f"  Requests: {result.stats.total_requests}\n")
        header.append(f"  Findings: ", style="")
        header.append(str(len(result.findings)), style="bold red" if result.findings else "bold green")

        console.print(Panel(header, border_style="cyan", title="Scan Summary", expand=True))
        console.print()

        # ── Findings table ────────────────────────────────────────
        if result.findings:
            table = Table(
                title="Vulnerability Findings",
                show_lines=True,
                border_style="dim",
                header_style="bold cyan",
                expand=True,
            )
            table.add_column("Severity", width=10, justify="center")
            table.add_column("Title", min_width=20, ratio=3)
            table.add_column("URL", min_width=15, ratio=3)
            table.add_column("Parameter", width=15)
            table.add_column("Confidence", width=10, justify="center")

            sorted_findings = sorted(
                result.findings,
                key=lambda f: _severity_sort_key(f.severity),
            )

            for finding in sorted_findings:
                sev = finding.severity.value
                style = _SEV_STYLE.get(sev, "")

                sev_text = Text(f" {sev.upper()} ", style=style)
                url_text = Text(
                    finding.url[:60] + ("…" if len(finding.url) > 60 else ""),
                    style="dim",
                )
                param_text = Text(
                    finding.parameter[:20] if finding.parameter else "—",
                    style="cyan",
                )
                conf = f"{finding.confidence:.0%}"

                table.add_row(sev_text, finding.title, url_text, param_text, conf)

            console.print(table)
            console.print()

            # ── Detailed remediation ──────────────────────────────
            for finding in sorted_findings:
                if self.verbose:
                    remediation = finding.remediation or "No remediation available."
                else:
                    remediation = finding.remediation or "No remediation available."
                    if len(remediation) > 120:
                        remediation = remediation[:117] + "..."

                sev = finding.severity.value
                emoji = finding.severity.emoji
                console.print(
                    f"  {emoji} [bold]{finding.title}[/bold] "
                    f"[dim]({finding.url})[/dim]"
                )
                console.print(f"     └─ {remediation}", style="dim")
                if self.verbose and finding.evidence:
                    console.print(f"     └─ Evidence: {finding.evidence[:200]}", style="dim italic")
                console.print()

        else:
            console.print(
                Panel(
                    "✅ No vulnerabilities found. The target appears secure based on "
                    "the tests that were run.",
                    border_style="green",
                    title="Result",
                ),
            )
            console.print()

        # ── Severity summary panel ────────────────────────────────
        counts = {level.value: 0 for level in SeverityLevel}
        for f in result.findings:
            counts[f.severity.value] += 1

        summary_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = counts[sev]
            if count > 0:
                emoji = SeverityLevel(sev).emoji
                summary_parts.append(f"{emoji} {sev.upper()}: {count}")

        if summary_parts:
            summary_text = "  │  ".join(summary_parts)
            console.print(
                Panel(
                    summary_text,
                    border_style="yellow",
                    title="Severity Breakdown",
                    expand=True,
                ),
            )
        console.print()

    @staticmethod
    def _print_fallback(result: ScanResult) -> None:
        """Fallback terminal output when Rich is not available."""
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

        for f in sorted(result.findings, key=lambda x: _severity_sort_key(x.severity)):
            print(f"\n  [{f.severity.value.upper()}] {f.title}")
            print(f"    URL:       {f.url}")
            if f.parameter:
                print(f"    Parameter: {f.parameter}")
            if f.remediation:
                print(f"    Fix:       {f.remediation[:100]}")
        print()


def _severity_sort_key(severity: SeverityLevel) -> int:
    """Return sort key (0=critical first)."""
    order = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 4,
    }
    return order.get(severity, 5)
