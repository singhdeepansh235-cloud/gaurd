"""Scan configuration for Sentinal-Fuzz.

Defines all knobs that control crawler depth, fuzzer concurrency,
timeouts, rate limits, output, and authentication. Uses a dataclass
with sensible defaults so that a beginner can run a scan with just
a target URL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class ScanProfile(Enum):
    """Predefined scan intensity profiles.

    Each profile adjusts depth, concurrency, and template selection
    to balance speed vs. thoroughness.

    Attributes:
        QUICK:     Fast surface-level scan. Depth 2, low concurrency.
        STANDARD:  Balanced scan. Depth 3, moderate concurrency.
        THOROUGH:  Deep scan. Depth 5, high concurrency, all templates.
    """

    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"

    @property
    def defaults(self) -> dict[str, int]:
        """Return profile-specific default overrides."""
        return {
            ScanProfile.QUICK: {"depth": 2, "concurrency": 10, "rate_limit": 30},
            ScanProfile.STANDARD: {"depth": 3, "concurrency": 20, "rate_limit": 50},
            ScanProfile.THOROUGH: {"depth": 5, "concurrency": 40, "rate_limit": 100},
        }[self]


@dataclass
class ScanConfig:
    """Configuration for a single scan run.

    All fields have sensible defaults. Only ``target`` is required.

    Example::

        config = ScanConfig(target="https://example.com")
        config = ScanConfig(
            target="https://example.com",
            depth=5,
            concurrency=40,
            scan_profile="thorough",
            auth_cookie="session=abc123",
        )

    Attributes:
        target:        The base URL of the target application.
        depth:         Maximum crawl depth from the target URL.
        concurrency:   Maximum number of concurrent HTTP requests.
        timeout:       HTTP request timeout in seconds.
        output_format: Report output format.
        output_dir:    Directory to write report files into.
        templates:     List of template IDs or ["all"] for all templates.
        auth_cookie:   Cookie string for authenticated scanning.
        auth_header:   Authorization header value (e.g., "Bearer <token>").
        proxy:         HTTP/SOCKS proxy URL (e.g., "http://127.0.0.1:8080").
        rate_limit:    Maximum requests per second (0 = unlimited).
        scan_profile:  Predefined profile that sets sensible defaults.
        user_agent:    Custom User-Agent string.
        follow_redirects: Whether to follow HTTP redirects.
        max_response_size: Maximum response body size to capture (bytes).
        js_rendering:  Enable Playwright-based JavaScript rendering.
        scope_patterns: Regex patterns to restrict crawling scope.
        exclude_patterns: Regex patterns to exclude from crawling.
        verbose:       Enable verbose/debug logging output.
    """

    target: str
    depth: int = 3
    concurrency: int = 20
    timeout: int = 10
    output_format: Literal["json", "html", "both"] = "both"
    output_dir: str = "reports"
    templates: list[str] = field(default_factory=lambda: ["all"])
    auth_cookie: str | None = None
    auth_header: str | None = None
    proxy: str | None = None
    rate_limit: int = 50
    scan_profile: Literal["quick", "standard", "thorough"] = "standard"
    user_agent: str = "Sentinal-Fuzz/0.1.0"
    follow_redirects: bool = True
    max_response_size: int = 5 * 1024 * 1024  # 5 MB
    js_rendering: bool = False
    scope_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    verbose: bool = False

    def __post_init__(self) -> None:
        """Apply scan profile defaults and validate configuration."""
        # Normalize target URL
        if not self.target.startswith(("http://", "https://")):
            self.target = f"https://{self.target}"
        self.target = self.target.rstrip("/")

        # Apply profile defaults (only override fields still at class defaults)
        profile = ScanProfile(self.scan_profile)
        profile_defaults = profile.defaults
        if self.depth == 3:
            self.depth = profile_defaults["depth"]
        if self.concurrency == 20:
            self.concurrency = profile_defaults["concurrency"]
        if self.rate_limit == 50:
            self.rate_limit = profile_defaults["rate_limit"]

        self._validate()

    def _validate(self) -> None:
        """Validate configuration values."""
        if not self.target:
            raise ValueError("target URL is required")
        if self.depth < 1:
            raise ValueError(f"depth must be >= 1, got {self.depth}")
        if self.concurrency < 1:
            raise ValueError(f"concurrency must be >= 1, got {self.concurrency}")
        if self.timeout < 1:
            raise ValueError(f"timeout must be >= 1, got {self.timeout}")
        if self.rate_limit < 0:
            raise ValueError(f"rate_limit must be >= 0, got {self.rate_limit}")

    @classmethod
    def from_dict(cls, data: dict) -> ScanConfig:  # type: ignore[type-arg]
        """Create a ScanConfig from a dictionary (e.g., parsed YAML/JSON config file)."""
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)
