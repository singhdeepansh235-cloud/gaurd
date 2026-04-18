"""Reporter factory — one function to get any report generator.

Supported formats: ``json``, ``html``, ``sarif``, ``terminal``, ``all``.

Usage::

    from sentinal_fuzz.reporter.reporter_factory import get_reporter

    reporter = get_reporter("html", output_dir="reports")
    filepath = reporter.generate(scan_result)

    # Or generate all formats at once
    reporters = get_reporter("all", output_dir="reports")
    for r in reporters:
        r.generate(scan_result)
"""

from __future__ import annotations

from sentinal_fuzz.reporter.base import BaseReporter
from sentinal_fuzz.reporter.html_reporter import HtmlReporter
from sentinal_fuzz.reporter.json_reporter import JsonReporter
from sentinal_fuzz.reporter.sarif_reporter import SarifReporter
from sentinal_fuzz.reporter.terminal_reporter import TerminalReporter
from sentinal_fuzz.utils.logger import get_logger

log = get_logger("reporter_factory")


class UnsupportedFormatError(ValueError):
    """Raised when an unknown report format is requested."""


def get_reporter(
    fmt: str,
    *,
    output_dir: str = "reports",
    verbose: bool = False,
) -> BaseReporter | list[BaseReporter]:
    """Create a reporter instance for the given format.

    Args:
        fmt:        Report format. One of: ``json``, ``html``, ``sarif``,
                    ``terminal``, ``all``.
        output_dir: Directory for file-based reporters.
        verbose:    If True, terminal reporter shows full details.

    Returns:
        A single ``BaseReporter`` for ``json``/``html``/``sarif``/``terminal``,
        or a list of reporters for ``all``.

    Raises:
        UnsupportedFormatError: If *fmt* is not a recognized format.
    """
    fmt_lower = fmt.lower().strip()

    if fmt_lower == "json":
        return JsonReporter(output_dir=output_dir)

    if fmt_lower == "html":
        return HtmlReporter(output_dir=output_dir)

    if fmt_lower == "sarif":
        return SarifReporter(output_dir=output_dir)

    if fmt_lower == "terminal":
        return TerminalReporter(output_dir=output_dir, verbose=verbose)

    if fmt_lower == "both":
        return [
            JsonReporter(output_dir=output_dir),
            HtmlReporter(output_dir=output_dir),
        ]

    if fmt_lower == "all":
        return [
            JsonReporter(output_dir=output_dir),
            HtmlReporter(output_dir=output_dir),
            TerminalReporter(output_dir=output_dir, verbose=verbose),
        ]

    raise UnsupportedFormatError(
        f"Unsupported report format '{fmt}'. "
        f"Supported: json, html, sarif, terminal, all"
    )


def get_all_reporters(
    *,
    output_dir: str = "reports",
    verbose: bool = False,
) -> list[BaseReporter]:
    """Convenience function to get all reporters.

    Returns:
        List of all file-based reporters plus the terminal reporter.
    """
    result = get_reporter("all", output_dir=output_dir, verbose=verbose)
    assert isinstance(result, list)
    return result
