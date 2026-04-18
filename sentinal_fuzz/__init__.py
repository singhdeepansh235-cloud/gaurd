"""Sentinal-Fuzz — Intelligent DAST Scanner."""

__version__ = "0.1.0"

__all__ = [
    "Endpoint",
    "Finding",
    "HttpExchange",
    "ScanConfig",
    "ScanResult",
    "ScanStats",
    "Scanner",
    "SeverityLevel",
    "__version__",
]


def __getattr__(name: str):
    """Lazily expose common package exports without forcing heavy imports."""
    if name == "ScanConfig":
        from sentinal_fuzz.core.config import ScanConfig

        return ScanConfig
    if name in {"Endpoint", "Finding", "HttpExchange", "ScanResult", "ScanStats", "SeverityLevel"}:
        from sentinal_fuzz.core import models

        return getattr(models, name)
    if name == "Scanner":
        from sentinal_fuzz.core.scanner import Scanner

        return Scanner
    raise AttributeError(f"module 'sentinal_fuzz' has no attribute {name!r}")
