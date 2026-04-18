"""Configuration loader for Sentinal-Fuzz.

Merges configuration from three sources (highest priority first):

    1. CLI flags          (always win)
    2. Environment vars   (SENTINAL_*)
    3. YAML config file   (lowest priority — base defaults)

Usage::

    from sentinal_fuzz.config_loader import build_config

    config = build_config(
        config_file="sentinal.yaml",
        cli_overrides={"depth": 5, "verbose": True},
    )
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from sentinal_fuzz.core.config import ScanConfig


# ── Environment variable mapping ──────────────────────────────────
# Maps env var names → ScanConfig field names.
_ENV_MAP: dict[str, str] = {
    "SENTINAL_TARGET": "target",
    "SENTINAL_PROXY": "proxy",
    "SENTINAL_AUTH_COOKIE": "auth_cookie",
    "SENTINAL_AUTH_HEADER": "auth_header",
    "SENTINAL_DEPTH": "depth",
    "SENTINAL_CONCURRENCY": "concurrency",
    "SENTINAL_TIMEOUT": "timeout",
    "SENTINAL_RATE_LIMIT": "rate_limit",
    "SENTINAL_OUTPUT_DIR": "output_dir",
    "SENTINAL_PROFILE": "scan_profile",
    "SENTINAL_VERBOSE": "verbose",
}

# Fields that should be cast to int
_INT_FIELDS = {"depth", "concurrency", "timeout", "rate_limit", "max_response_size"}

# Fields that should be cast to bool
_BOOL_FIELDS = {"verbose", "follow_redirects", "js_rendering"}


def load_yaml_config(filepath: str | Path) -> dict[str, Any]:
    """Read and parse a YAML configuration file.

    Args:
        filepath: Path to the YAML file.

    Returns:
        A dictionary of configuration values.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Config path is not a file: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(data).__name__}")

    return data


def _collect_env_vars() -> dict[str, Any]:
    """Read SENTINAL_* environment variables and map to config fields."""
    env_config: dict[str, Any] = {}

    for env_name, field_name in _ENV_MAP.items():
        value = os.environ.get(env_name)
        if value is None:
            continue

        # Type coercion
        if field_name in _INT_FIELDS:
            try:
                env_config[field_name] = int(value)
            except ValueError:
                pass  # skip invalid int env vars silently
        elif field_name in _BOOL_FIELDS:
            env_config[field_name] = value.lower() in ("1", "true", "yes")
        else:
            env_config[field_name] = value

    return env_config


def _normalise_cli_overrides(cli: dict[str, Any]) -> dict[str, Any]:
    """Remove None values and rename CLI flag names to config fields.

    Typer passes ``None`` for unset optional flags, so we strip those.
    """
    # Map CLI flag names that differ from ScanConfig field names
    renames: dict[str, str] = {
        "profile": "scan_profile",
        "output": "output_format",
        "output_dir": "output_dir",
        "exclude_path": "exclude_patterns",
        "js": "js_rendering",
    }

    cleaned: dict[str, Any] = {}
    for key, val in cli.items():
        if val is None:
            continue
        # Apply rename if needed
        config_key = renames.get(key, key)
        cleaned[config_key] = val

    return cleaned


def build_config(
    *,
    config_file: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    target: str | None = None,
) -> ScanConfig:
    """Build a ``ScanConfig`` by merging all configuration sources.

    Priority: CLI flags  >  environment vars  >  YAML config file

    Args:
        config_file:    Optional path to a YAML config file.
        cli_overrides:  Dict of CLI flags and their values.
        target:         Target URL (convenience — also accepted in cli_overrides).

    Returns:
        A validated ``ScanConfig`` instance.

    Raises:
        FileNotFoundError: If the config file is specified but missing.
        ValueError: If required values are missing after merging.
    """
    merged: dict[str, Any] = {}

    # Layer 1: YAML config file (lowest priority)
    if config_file:
        yaml_data = load_yaml_config(config_file)
        merged.update(yaml_data)

    # Layer 2: Environment variables
    env_data = _collect_env_vars()
    merged.update(env_data)

    # Layer 3: CLI flags (highest priority)
    if cli_overrides:
        cleaned = _normalise_cli_overrides(cli_overrides)
        merged.update(cleaned)

    # Explicit target argument
    if target:
        merged["target"] = target

    # Handle templates: convert comma-string to list
    templates = merged.get("templates")
    if isinstance(templates, str):
        merged["templates"] = [t.strip() for t in templates.split(",") if t.strip()]

    # Handle exclude_patterns: ensure list
    exclude = merged.get("exclude_patterns")
    if isinstance(exclude, str):
        merged["exclude_patterns"] = [exclude]
    elif isinstance(exclude, tuple):
        merged["exclude_patterns"] = list(exclude)

    # Validate that we have a target
    if "target" not in merged or not merged["target"]:
        raise ValueError(
            "No target URL provided. Set it via:\n"
            "  • CLI argument:   sentinal-fuzz scan <URL>\n"
            "  • Config file:    target: https://example.com\n"
            "  • Environment:    SENTINAL_TARGET=https://example.com"
        )

    return ScanConfig.from_dict(merged)
