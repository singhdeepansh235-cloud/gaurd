"""Rich display components for Sentinal-Fuzz CLI.

All terminal UI rendering lives here so that ``cli.py`` stays focused
on argument parsing and orchestration.  Every public function uses Rich
objects (Panel, Table, Live, Console) — never bare ``print()``.

Layout architecture (inside ``ScanProgressDisplay``)::

    ┌─────────────────────────── TOP ──────────────────────────────┐
    │  Sentinal-Fuzz v0.1.0 │ Target: … │ Profile: … │ Elapsed:  │
    ├────────── LEFT (40%) ──────────┬─────── RIGHT (60%) ────────┤
    │  ┌ Crawl Progress ─────────┐  │  ┌ Findings ────────────┐  │
    │  │ URLs found:     47      │  │  │ [HIGH] XSS at /…     │  │
    │  │ Forms:          12      │  │  │ [MEDIUM] CSP on /…   │  │
    │  └─────────────────────────┘  │  │ [CRITICAL] SQLi …    │  │
    │  ┌ Fuzzing Progress ───────┐  │  └──────────────────────┘  │
    │  │ Tested: 23/47           │  │                            │
    │  │ Req/sec: 42.3           │  │                            │
    │  └─────────────────────────┘  │                            │
    ├───────────────────────── BOTTOM ────────────────────────────┤
    │  Scanning... ████████░░░░░░░ 58%   (27/47 endpoints)       │
    └─────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import io
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

# Force UTF-8 on Windows so Rich box-drawing characters render correctly
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.progress import Progress as RichProgress
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from sentinal_fuzz.analyzer.aggregator import AnalysisReport
    from sentinal_fuzz.core.models import Finding, ScanResult

# ── Shared console (stdout, not stderr — Rich logger uses stderr) ──
console = Console(force_terminal=True)

# ── Severity color constants ──────────────────────────────────────
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim white",
}

# Internal lowercase lookup (used across helpers)
_SEV_STYLE: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}

_SEV_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

# Maximum findings visible in the live feed before scrolling
_MAX_VISIBLE_FINDINGS = 10


# ────────────────────────────────────────────────────────────────────
#  Banner
# ────────────────────────────────────────────────────────────────────

_BANNER = r"""[bold cyan]
 ____            _   _             _        _____
/ ___|  ___ _ __|  |_(_)_ __   __ _| |      |  ___|   _ ________
\___ \ / _ \ '_ \| __| | '_ \ / _` | |_____ | |_ | | | |_  /_  /
 ___) |  __/ | | | |_| | | | | (_| | |______||  _|| |_| |/ / / /
|____/ \___|_| |_|\__|_|_| |_|\__,_|_|      |_|   \__,_/___/___|
[/bold cyan]"""


def display_banner(version: str) -> None:
    """Print the ASCII art banner with version info."""
    console.print(_BANNER)
    console.print(
        Align.center(
            Text.from_markup(
                f"[dim]v{version} — Intelligent DAST Scanner[/dim]"
            )
        )
    )
    console.print()


# ────────────────────────────────────────────────────────────────────
#  Helpers — format elapsed time
# ────────────────────────────────────────────────────────────────────

def _fmt_elapsed(seconds: float) -> str:
    """Format seconds as HH:MM:SS."""
    hours, rem = divmod(int(seconds), 3600)
    mins, secs = divmod(rem, 60)
    return f"{hours:02d}:{mins:02d}:{secs:02d}"


def _fmt_eta(seconds: float | None) -> str:
    """Format ETA seconds into a human-friendly string."""
    if seconds is None or seconds <= 0:
        return "—"
    if seconds < 60:
        return f"~{int(seconds)}s"
    mins, secs = divmod(int(seconds), 60)
    return f"~{mins}m {secs:02d}s"


def _severity_style(severity_str: str) -> str:
    """Return a Rich style for the given severity string."""
    return SEVERITY_COLORS.get(severity_str.upper(), "dim white")


# ────────────────────────────────────────────────────────────────────
#  Scan progress (live-updating multi-panel layout)
# ────────────────────────────────────────────────────────────────────

@dataclass
class _FindingEntry:
    """Lightweight snapshot of a finding for the live feed."""
    severity: str
    title: str
    url: str


@dataclass
class ScanProgressDisplay:
    """Live-updating Rich TUI that tracks scan metrics in real time.

    Uses ``rich.live.Live`` with a ``Layout`` containing four regions:
    top info bar, left stats panels, right findings feed, and a bottom
    progress bar.

    Usage::

        display = ScanProgressDisplay(target="https://example.com")
        display.start()
        display.update_crawl_stats(urls_found=5, forms=2, apis=1, current_url="/api")
        display.update_fuzz_stats(tested=3, total=10, requests_sent=120, req_per_sec=40.0)
        display.add_finding(finding)
        display.stop(summary_report)
    """

    # -- Config fields (set at construction) --
    target: str = "—"
    profile: str = "standard"
    version: str = "0.1.0"

    # -- Crawl stats --
    urls_found: int = 0
    forms_discovered: int = 0
    api_endpoints: int = 0
    current_url: str = "—"

    # -- Fuzz stats --
    endpoints_tested: int = 0
    endpoints_total: int = 0
    requests_sent: int = 0
    req_per_sec: float = 0.0
    eta_seconds: float | None = None

    # -- Internal --
    findings_count: int = 0
    current_stage: str = "Initializing"
    _start_time: float = field(default_factory=time.monotonic)
    _live: Live | None = field(default=None, init=False, repr=False)
    _findings_feed: list[_FindingEntry] = field(default_factory=list, init=False)
    _progress: RichProgress | None = field(default=None, init=False, repr=False)
    _progress_task_id: object = field(default=None, init=False, repr=False)

    # ── lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        """Begin the live display."""
        self._start_time = time.monotonic()

        # Build the embedded progress bar
        self._progress = RichProgress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(
                bar_width=None,
                style="bar.back",
                complete_style="cyan",
                finished_style="bold green",
                pulse_style="cyan",
            ),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]endpoints[/dim]"),
            TimeRemainingColumn(),
            expand=True,
        )
        self._progress_task_id = self._progress.add_task(
            "Scanning...",
            total=max(self.endpoints_total, 1),
            completed=self.endpoints_tested,
        )

        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

    def stop(self, summary: AnalysisReport | None = None) -> None:
        """Stop the live display, optionally printing a final summary.

        Args:
            summary: If provided, a rich summary table is printed after
                     the live display stops.
        """
        if self._live:
            self._live.update(self._build_layout())
            self._live.stop()
            self._live = None

        if summary is not None:
            self._print_final_summary(summary)

    def refresh(self) -> None:
        """Force a refresh of the live layout."""
        if self._live:
            # Sync the progress bar
            if self._progress and self._progress_task_id is not None:
                self._progress.update(
                    self._progress_task_id,  # type: ignore[arg-type]
                    total=max(self.endpoints_total, 1),
                    completed=self.endpoints_tested,
                )
            self._live.update(self._build_layout())

    # ── public update methods ─────────────────────────────────────

    def set_stage(self, stage: str) -> None:
        self.current_stage = stage
        if self._progress and self._progress_task_id is not None:
            self._progress.update(
                self._progress_task_id,  # type: ignore[arg-type]
                description=stage,
            )
        self.refresh()

    def update_crawl_stats(
        self,
        urls_found: int | None = None,
        forms: int | None = None,
        apis: int | None = None,
        current_url: str | None = None,
    ) -> None:
        """Update the crawl progress panel."""
        if urls_found is not None:
            self.urls_found = urls_found
        if forms is not None:
            self.forms_discovered = forms
        if apis is not None:
            self.api_endpoints = apis
        if current_url is not None:
            self.current_url = current_url
        self.refresh()

    def update_fuzz_stats(
        self,
        tested: int | None = None,
        total: int | None = None,
        requests_sent: int | None = None,
        req_per_sec: float | None = None,
        eta_seconds: float | None = None,
    ) -> None:
        """Update the fuzzing progress panel."""
        if tested is not None:
            self.endpoints_tested = tested
        if total is not None:
            self.endpoints_total = total
        if requests_sent is not None:
            self.requests_sent = requests_sent
        if req_per_sec is not None:
            self.req_per_sec = req_per_sec
        if eta_seconds is not None:
            self.eta_seconds = eta_seconds
        self.refresh()

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the live findings feed.

        If more than ``_MAX_VISIBLE_FINDINGS`` entries exist the oldest
        are scrolled off.
        """
        sev = finding.severity.value.upper()
        self._findings_feed.append(
            _FindingEntry(severity=sev, title=finding.title, url=finding.url)
        )
        self.findings_count = len(self._findings_feed)
        self.refresh()

    # ── legacy helpers (backward compat from old API) ─────────────

    def update_urls(self, count: int) -> None:
        self.urls_found = count
        self.refresh()

    def update_requests(self, count: int) -> None:
        self.requests_sent = count
        elapsed = time.monotonic() - self._start_time
        self.req_per_sec = count / max(elapsed, 0.001)
        self.refresh()

    def increment_findings(self) -> None:
        # Only increment the counter (finding detail added via add_finding)
        self.findings_count += 1
        self.refresh()

    # ── layout builders ───────────────────────────────────────────

    def _build_layout(self) -> Layout:
        """Assemble the full 4-region layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="top", size=3),
            Layout(name="body", ratio=1),
            Layout(name="bottom", size=3),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=2),    # 40%
            Layout(name="right", ratio=3),   # 60%
        )

        layout["top"].update(self._build_info_bar())
        layout["left"].update(self._build_left_panels())
        layout["right"].update(self._build_findings_panel())
        layout["bottom"].update(self._build_progress_bar())

        return layout

    def _build_info_bar(self) -> Panel:
        """TOP PANEL: Scan info bar."""
        elapsed = time.monotonic() - self._start_time

        info = Text.from_markup(
            f"  [bold cyan]Sentinal-Fuzz[/bold cyan] [dim]v{self.version}[/dim]"
            f"  [dim]│[/dim]  Target: [bold green]{self.target}[/bold green]"
            f"  [dim]│[/dim]  Profile: [bold magenta]{self.profile}[/bold magenta]"
            f"  [dim]│[/dim]  Elapsed: [bold white]{_fmt_elapsed(elapsed)}[/bold white]"
            f"  [dim]│[/dim]  Stage: [bold cyan]{self.current_stage}[/bold cyan]"
        )

        return Panel(
            info,
            border_style="cyan",
            padding=(0, 0),
        )

    def _build_left_panels(self) -> Group:
        """LEFT PANEL: Crawl progress + Fuzzing progress."""
        # -- Crawl Progress Panel --
        crawl_table = Table.grid(padding=(0, 2))
        crawl_table.add_column(style="bold cyan", justify="right", min_width=20)
        crawl_table.add_column(style="bold white", min_width=12)

        crawl_table.add_row("URLs found:", f"[bold]{self.urls_found}[/bold]")
        crawl_table.add_row("Forms discovered:", f"[bold]{self.forms_discovered}[/bold]")
        crawl_table.add_row("API endpoints:", f"[bold]{self.api_endpoints}[/bold]")

        # Truncate current URL for display
        display_url = self.current_url
        if len(display_url) > 35:
            display_url = "…" + display_url[-34:]
        crawl_table.add_row("Current URL:", f"[dim]{display_url}[/dim]")

        crawl_panel = Panel(
            crawl_table,
            title="[bold cyan]🕷️  Crawl Progress[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

        # -- Fuzzing Progress Panel --
        fuzz_table = Table.grid(padding=(0, 2))
        fuzz_table.add_column(style="bold cyan", justify="right", min_width=20)
        fuzz_table.add_column(style="bold white", min_width=12)

        total_display = self.endpoints_total or "?"
        fuzz_table.add_row(
            "Endpoints tested:",
            f"[bold]{self.endpoints_tested}[/bold] / {total_display}",
        )
        fuzz_table.add_row(
            "Requests sent:",
            f"[bold]{self.requests_sent:,}[/bold]",
        )
        fuzz_table.add_row(
            "Req/sec:",
            f"[bold]{self.req_per_sec:.1f}[/bold]",
        )
        fuzz_table.add_row(
            "ETA:",
            f"[bold]{_fmt_eta(self.eta_seconds)}[/bold]",
        )

        fuzz_panel = Panel(
            fuzz_table,
            title="[bold cyan]⚡ Fuzzing Progress[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

        # -- Findings counter (compact) --
        sev_counts: dict[str, int] = {}
        for entry in self._findings_feed:
            sev_counts[entry.severity] = sev_counts.get(entry.severity, 0) + 1

        counter_parts: list[str] = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = sev_counts.get(sev, 0)
            if count > 0:
                style = SEVERITY_COLORS.get(sev, "dim")
                counter_parts.append(f"[{style}]{sev}: {count}[/{style}]")

        if counter_parts:
            counter_text = "  ".join(counter_parts)
        else:
            counter_text = "[dim]None yet[/dim]"

        summary_panel = Panel(
            Text.from_markup(f"  Total: [bold]{self.findings_count}[/bold]   {counter_text}"),
            title="[bold cyan]📊 Findings Summary[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

        return Group(crawl_panel, fuzz_panel, summary_panel)

    def _build_findings_panel(self) -> Panel:
        """RIGHT PANEL: Live findings feed, color-coded by severity."""
        table = Table.grid(padding=(0, 1))
        table.add_column(width=12, justify="center")  # severity badge
        table.add_column(ratio=1)                       # title + url

        visible = self._findings_feed[-_MAX_VISIBLE_FINDINGS:]

        if visible:
            for entry in visible:
                style = SEVERITY_COLORS.get(entry.severity, "dim white")
                badge = Text(f"[{entry.severity}]", style=style)

                # Truncate title for readability
                title = entry.title
                if len(title) > 50:
                    title = title[:47] + "..."
                url_short = entry.url
                if len(url_short) > 40:
                    url_short = "…" + url_short[-39:]

                detail = Text.from_markup(
                    f"[{style}]{title}[/{style}]\n"
                    f"  [dim]{url_short}[/dim]"
                )
                table.add_row(badge, detail)
        else:
            table.add_row(
                "",
                Text.from_markup(
                    "[dim italic]No findings yet — scan in progress…[/dim italic]"
                ),
            )

        # Show scroll indicator
        total = len(self._findings_feed)
        scroll_info = ""
        if total > _MAX_VISIBLE_FINDINGS:
            scroll_info = f" [dim]({total - _MAX_VISIBLE_FINDINGS} more above ↑)[/dim]"

        return Panel(
            table,
            title=f"[bold cyan]🔍 Findings[/bold cyan]{scroll_info}",
            border_style="cyan",
            padding=(0, 1),
        )

    def _build_progress_bar(self) -> Panel:
        """BOTTOM: Progress bar powered by rich.progress."""
        if self._progress is not None:
            return Panel(
                self._progress,
                border_style="cyan",
                padding=(0, 1),
            )
        # Fallback when progress bar isn't initialized
        return Panel(
            Text.from_markup("[dim]Waiting to start…[/dim]"),
            border_style="dim",
            padding=(0, 1),
        )

    # ── final summary (printed after stop()) ──────────────────────

    def _print_final_summary(self, report: AnalysisReport) -> None:
        """Print a polished final summary table after the scan completes."""
        console.print()
        console.print(Rule("[bold cyan]🛡️  Scan Complete[/bold cyan]"))
        console.print()

        # -- Severity breakdown table --
        table = Table(
            title="[bold cyan]Vulnerability Summary[/bold cyan]",
            show_header=True,
            header_style="bold",
            border_style="cyan",
            show_lines=True,
            pad_edge=True,
            expand=True,
        )
        table.add_column("Severity", justify="center", min_width=12)
        table.add_column("Count", justify="center", min_width=8)
        table.add_column("Example Finding", ratio=1)

        total_count = 0
        for sev_display, sev_key in [
            ("CRITICAL", "Critical"),
            ("HIGH", "High"),
            ("MEDIUM", "Medium"),
            ("LOW", "Low"),
            ("INFO", "Info"),
        ]:
            count = report.by_severity.get(sev_key, 0)
            total_count += count
            style = SEVERITY_COLORS.get(sev_display, "dim")
            emoji = _SEV_EMOJI.get(sev_display.lower(), "")

            # Find an example finding from the feed
            example = "—"
            for entry in self._findings_feed:
                if entry.severity == sev_display:
                    example = f"{entry.title}"
                    break

            if count > 0:
                table.add_row(
                    Text(f"{emoji} {sev_display}", style=style),
                    Text(str(count), style=style),
                    Text(example, style="dim"),
                )
            else:
                table.add_row(
                    Text(f"{emoji} {sev_display}", style="dim"),
                    Text("0", style="dim"),
                    Text("—", style="dim"),
                )

        # Total row
        table.add_row(
            Text("TOTAL", style="bold"),
            Text(str(total_count), style="bold"),
            Text(""),
        )

        console.print(table)
        console.print()

        # -- Risk score --
        risk = report.risk_score
        if risk >= 70:
            risk_style = "bold red"
            risk_label = "CRITICAL"
        elif risk >= 40:
            risk_style = "bold yellow"
            risk_label = "HIGH"
        elif risk >= 15:
            risk_style = "yellow"
            risk_label = "MEDIUM"
        else:
            risk_style = "bold green"
            risk_label = "LOW"

        console.print(
            f"  Risk Score: [{risk_style}]{risk:.1f}/100 ({risk_label})[/{risk_style}]"
        )
        console.print(
            f"  Scan Coverage: [cyan]{report.scan_coverage:.1f}%[/cyan]"
        )
        console.print()

        # -- Report path --
        now = datetime.now()
        report_filename = f"scan_{now.strftime('%Y-%m-%d_%H%M%S')}.html"
        console.print(
            f"  Report saved to: [bold cyan]./reports/{report_filename}[/bold cyan]"
        )
        console.print()


# ────────────────────────────────────────────────────────────────────
#  Finding display (printed as each finding is discovered)
# ────────────────────────────────────────────────────────────────────

def display_finding(finding: Finding) -> None:
    """Print a single finding as a styled Rich panel."""
    sev = finding.severity.value
    style = _SEV_STYLE.get(sev, "dim")
    emoji = _SEV_EMOJI.get(sev, "")

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", justify="right", min_width=12)
    grid.add_column()

    grid.add_row("Severity", Text(sev.upper(), style=style))
    grid.add_row("URL", finding.url)
    if finding.parameter:
        grid.add_row("Parameter", finding.parameter)
    if finding.payload:
        grid.add_row("Payload", Text(finding.payload[:120], style="dim"))
    if finding.evidence:
        grid.add_row("Evidence", Text(finding.evidence[:200], style="italic"))
    if finding.cwe:
        grid.add_row("CWE", finding.cwe)
    if finding.owasp:
        grid.add_row("OWASP", finding.owasp)
    if finding.confidence < 1.0:
        grid.add_row("Confidence", f"{finding.confidence:.0%}")

    panel = Panel(
        grid,
        title=f"[{style}]{emoji} {finding.title}[/{style}]",
        border_style=style,
        padding=(0, 1),
    )
    console.print(panel)


# ────────────────────────────────────────────────────────────────────
#  Summary table (printed after scan completes)
# ────────────────────────────────────────────────────────────────────

def display_summary(result: ScanResult) -> None:
    """Print the final scan summary with findings grouped by severity."""
    console.print()
    console.print(Rule("[bold cyan]Scan Summary[/bold cyan]"))
    console.print()

    # ── overview metrics ───────────────────────────────────────────
    info_table = Table.grid(padding=(0, 3))
    info_table.add_column(style="bold", justify="right")
    info_table.add_column()

    info_table.add_row("Target", result.target)
    info_table.add_row("Scan ID", result.scan_id)
    info_table.add_row("Profile", result.scan_profile)
    info_table.add_row("Duration", f"{result.duration_seconds:.1f}s")
    info_table.add_row("Endpoints", str(len(result.endpoints)))
    info_table.add_row("Requests", str(result.stats.total_requests))
    info_table.add_row(
        "Throughput",
        f"{result.stats.requests_per_second:.1f} req/s",
    )

    console.print(
        Panel(info_table, title="[bold]Scan Info[/bold]", border_style="cyan")
    )
    console.print()

    # ── severity breakdown ─────────────────────────────────────────
    sev_table = Table(
        title="Findings by Severity",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        show_lines=False,
        pad_edge=True,
    )
    sev_table.add_column("Severity", justify="center", min_width=12)
    sev_table.add_column("Count", justify="center", min_width=8)

    for sev_name in ("critical", "high", "medium", "low", "info"):
        count = result.stats.findings_by_severity.get(sev_name, 0)
        style = _SEV_STYLE.get(sev_name, "")
        emoji = _SEV_EMOJI.get(sev_name, "")
        sev_table.add_row(
            Text(f"{emoji} {sev_name.upper()}", style=style),
            Text(str(count), style=style if count else "dim"),
        )

    console.print(sev_table)
    console.print()

    # ── detailed findings table ────────────────────────────────────
    if result.findings:
        findings_table = Table(
            title="All Findings",
            show_header=True,
            header_style="bold",
            border_style="cyan",
            show_lines=True,
            expand=True,
        )
        findings_table.add_column("#", justify="center", width=4)
        findings_table.add_column("Severity", justify="center", width=10)
        findings_table.add_column("Title", min_width=25, ratio=2)
        findings_table.add_column("URL", ratio=2)
        findings_table.add_column("Parameter", width=12)
        findings_table.add_column("CWE", width=10)

        for idx, finding in enumerate(result.findings, 1):
            sev = finding.severity.value
            style = _SEV_STYLE.get(sev, "")
            emoji = _SEV_EMOJI.get(sev, "")
            findings_table.add_row(
                str(idx),
                Text(f"{emoji} {sev.upper()}", style=style),
                finding.title,
                Text(finding.url, style="dim"),
                finding.parameter or "—",
                finding.cwe or "—",
            )

        console.print(findings_table)
    else:
        console.print(
            Panel(
                "[green]✅ No vulnerabilities found![/green]",
                border_style="green",
            )
        )

    console.print()


# ────────────────────────────────────────────────────────────────────
#  Template list display
# ────────────────────────────────────────────────────────────────────

def display_template_list(templates: list[dict[str, object]]) -> None:
    """Print a styled table of available fuzzing templates."""
    table = Table(
        title="[bold cyan]📋 Fuzzing Templates[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("ID", style="bold cyan", min_width=20)
    table.add_column("Name", min_width=25)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Tags", ratio=1)
    table.add_column("Payloads", justify="center", width=10)

    for tmpl in templates:
        info = tmpl.get("info", {})
        sev = str(info.get("severity", "info")).lower()  # type: ignore[union-attr]
        style = _SEV_STYLE.get(sev, "")
        emoji = _SEV_EMOJI.get(sev, "")
        tags = ", ".join(info.get("tags", []))  # type: ignore[union-attr]

        # Count payloads
        payload_count = 0
        for req in tmpl.get("requests", []):
            payload_count += len(req.get("payloads", []))  # type: ignore[union-attr]

        table.add_row(
            str(tmpl.get("id", "?")),
            str(info.get("name", "Unknown")),  # type: ignore[union-attr]
            Text(f"{emoji} {sev.upper()}", style=style),
            Text(tags, style="dim"),
            str(payload_count),
        )

    console.print(table)
    console.print()


def display_template_validation(filepath: str, errors: list[str]) -> None:
    """Print template validation results."""
    if errors:
        console.print(
            Panel(
                "\n".join(f"[red]✗[/red] {e}" for e in errors),
                title=f"[bold red]Validation Failed: {filepath}[/bold red]",
                border_style="red",
            )
        )
    else:
        console.print(
            Panel(
                "[green]✓ Template is valid[/green]",
                title=f"[bold green]Validation Passed: {filepath}[/bold green]",
                border_style="green",
            )
        )


# ────────────────────────────────────────────────────────────────────
#  Error display
# ────────────────────────────────────────────────────────────────────

def display_error(message: str, *, hint: str = "") -> None:
    """Print a user-friendly error message (no traceback)."""
    body = f"[bold red]Error:[/bold red] {message}"
    if hint:
        body += f"\n[dim]{hint}[/dim]"
    console.print(
        Panel(body, border_style="red", title="[red]✗ Error[/red]")
    )


def display_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]✓[/green] {message}")


def display_info(message: str) -> None:
    """Print an informational message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")


# ────────────────────────────────────────────────────────────────────
#  Crawl output display
# ────────────────────────────────────────────────────────────────────

def display_crawl_results(endpoints: list[dict[str, object]], output_path: str) -> None:
    """Print crawl results summary."""
    table = Table(
        title="[bold cyan]🕷️ Crawl Results[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        show_lines=False,
        expand=True,
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("Method", justify="center", width=8)
    table.add_column("URL", ratio=3)
    table.add_column("Params", justify="center", width=8)
    table.add_column("Source", width=10)

    for idx, ep in enumerate(endpoints, 1):
        params = ep.get("params", {})
        table.add_row(
            str(idx),
            str(ep.get("method", "GET")),
            str(ep.get("url", "")),
            str(len(params)) if isinstance(params, dict) else "0",
            str(ep.get("source", "crawl")),
        )
        if idx >= 50:
            table.add_row("...", "...", f"[dim]+{len(endpoints) - 50} more[/dim]", "", "")
            break

    console.print(table)
    console.print()
    display_success(f"Saved {len(endpoints)} endpoints to [bold]{output_path}[/bold]")
