"""Tests for config_loader — YAML parsing, env var merge, CLI override."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from sentinal_fuzz.config_loader import build_config, load_yaml_config


# ── YAML loading ──────────────────────────────────────────────────

def test_load_yaml_config_basic(tmp_path: Path) -> None:
    """Load a simple YAML config file."""
    cfg_file = tmp_path / "test.yaml"
    cfg_file.write_text(yaml.dump({"target": "https://test.com", "depth": 5}))

    data = load_yaml_config(cfg_file)
    assert data["target"] == "https://test.com"
    assert data["depth"] == 5


def test_load_yaml_missing_file() -> None:
    """Raise FileNotFoundError for missing config."""
    with pytest.raises(FileNotFoundError):
        load_yaml_config("/nonexistent/path.yaml")


def test_load_yaml_empty_file(tmp_path: Path) -> None:
    """Return empty dict for empty YAML file."""
    cfg_file = tmp_path / "empty.yaml"
    cfg_file.write_text("")

    data = load_yaml_config(cfg_file)
    assert data == {}


# ── build_config (merge logic) ────────────────────────────────────

def test_build_config_target_required() -> None:
    """Raise ValueError when no target is provided."""
    with pytest.raises(ValueError, match="No target URL"):
        build_config()


def test_build_config_cli_override() -> None:
    """CLI overrides should win over defaults."""
    config = build_config(
        target="https://example.com",
        cli_overrides={"depth": 7, "timeout": 30},
    )
    assert config.depth == 7
    assert config.timeout == 30


def test_build_config_from_yaml(tmp_path: Path) -> None:
    """Load config from YAML file."""
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(yaml.dump({
        "target": "https://yaml-target.com",
        "depth": 4,
        "concurrency": 15,
    }))

    config = build_config(config_file=str(cfg_file))
    assert "yaml-target.com" in config.target
    assert config.concurrency == 15


def test_build_config_cli_overrides_yaml(tmp_path: Path) -> None:
    """CLI flags override YAML values."""
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(yaml.dump({
        "target": "https://yaml.com",
        "depth": 2,
    }))

    config = build_config(
        config_file=str(cfg_file),
        cli_overrides={"depth": 10},
    )
    assert config.depth == 10


def test_build_config_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables should be picked up."""
    monkeypatch.setenv("SENTINAL_TARGET", "https://env-target.com")
    monkeypatch.setenv("SENTINAL_PROXY", "http://127.0.0.1:8080")

    config = build_config()
    assert "env-target.com" in config.target
    assert config.proxy == "http://127.0.0.1:8080"


def test_build_config_templates_comma_string() -> None:
    """Templates given as comma string should become a list."""
    config = build_config(
        target="https://test.com",
        cli_overrides={"templates": "sqli,xss,csrf"},
    )
    assert config.templates == ["sqli", "xss", "csrf"]
