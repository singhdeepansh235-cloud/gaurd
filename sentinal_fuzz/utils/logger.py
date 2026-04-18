"""Structured logger for Sentinal-Fuzz.

Provides a factory function ``get_logger(name)`` that creates loggers
with Rich-powered colored console output. Colors are mapped to log
levels for quick visual scanning in the terminal.

Usage::

    from sentinal_fuzz.utils.logger import get_logger

    log = get_logger("crawler")
    log.info("Discovered %d endpoints", count)
    log.warning("Rate limited by target")
    log.error("Connection refused: %s", url)
"""

from __future__ import annotations

import logging
import sys
from typing import ClassVar

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── Theme ──────────────────────────────────────────────────────────
# Map log levels to Rich color styles for consistent terminal output.
_THEME = Theme({
    "logging.level.debug": "dim cyan",
    "logging.level.info": "cyan",
    "logging.level.warning": "bold yellow",
    "logging.level.error": "bold red",
    "logging.level.critical": "bold white on red",
})

# Shared console instance so all loggers write to the same output
_console = Console(theme=_THEME, stderr=True)


class SentinalFormatter(logging.Formatter):
    """Custom formatter that prefixes log records with a module tag.

    Format: ``[HH:MM:SS] LEVEL    module │ message``
    """

    LEVEL_COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[2m",       # dim
        logging.INFO: "\033[36m",       # cyan
        logging.WARNING: "\033[33m",    # yellow
        logging.ERROR: "\033[31m",      # red
        logging.CRITICAL: "\033[41m",   # red background
    }
    RESET = "\033[0m"


def get_logger(
    name: str,
    *,
    level: int = logging.INFO,
    rich_output: bool = True,
) -> logging.Logger:
    """Create and return a configured logger.

    Args:
        name:        Logger name, typically the module name (e.g., "crawler").
        level:       Minimum log level. Defaults to INFO.
        rich_output: If True, use Rich console handler for colored output.
                     If False, use a plain StreamHandler (useful for CI/tests).

    Returns:
        A configured ``logging.Logger`` instance.

    Example::

        log = get_logger("fuzzer", level=logging.DEBUG)
        log.debug("Payload: %s", payload)
    """
    logger = logging.getLogger(f"sentinal_fuzz.{name}")

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    if rich_output:
        handler = RichHandler(
            console=_console,
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            markup=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s │ %(message)s",
            datefmt="%H:%M:%S",
        ))

    logger.addHandler(handler)
    return logger


def set_global_level(level: int) -> None:
    """Set the log level for all sentinal_fuzz loggers.

    Args:
        level: The logging level (e.g., logging.DEBUG).
    """
    root = logging.getLogger("sentinal_fuzz")
    root.setLevel(level)
    for handler in root.handlers:
        handler.setLevel(level)
