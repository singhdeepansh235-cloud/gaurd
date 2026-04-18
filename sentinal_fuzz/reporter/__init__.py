"""Reporter module — scan result formatting and report generation.

Supported formats:
- **JSON**: Machine-readable, re-loadable scan data.
- **HTML**: Self-contained visual report with dark theme.
- **SARIF**: CI/CD integration (GitHub Code Scanning).
- **Terminal**: Rich-formatted console output.
"""

from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.reporter.html_reporter import HtmlReporter
from sentinal_fuzz.reporter.json_reporter import JsonReporter
from sentinal_fuzz.reporter.reporter_factory import (
    UnsupportedFormatError,
    get_all_reporters,
    get_reporter,
)
from sentinal_fuzz.reporter.sarif_reporter import SarifReporter
from sentinal_fuzz.reporter.terminal_reporter import TerminalReporter

__all__ = [
    "BaseReporter",
    "HtmlReporter",
    "JsonReporter",
    "SarifReporter",
    "TerminalReporter",
    "UnsupportedFormatError",
    "get_all_reporters",
    "get_reporter",
]
