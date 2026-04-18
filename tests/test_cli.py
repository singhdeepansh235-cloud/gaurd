"""Smoke tests for the CLI."""

from typer.testing import CliRunner

from sentinal_fuzz.cli import app

runner = CliRunner()


def test_main_help() -> None:
    """Verify the main --help works."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Sentinal-Fuzz" in result.output


def test_version_flag() -> None:
    """Verify --version prints the version string."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_scan_help() -> None:
    """Verify scan --help works and lists all options."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "TARGET" in result.output
    assert "--depth" in result.output
    assert "--concurrency" in result.output
    assert "--profile" in result.output
    assert "--proxy" in result.output
    assert "--rate-limit" in result.output
    assert "--timeout" in result.output
    assert "--exclude-path" in result.output


def test_crawl_help() -> None:
    """Verify crawl --help works."""
    result = runner.invoke(app, ["crawl", "--help"])
    assert result.exit_code == 0
    assert "TARGET" in result.output
    assert "--depth" in result.output
    assert "--js" in result.output


def test_template_list() -> None:
    """Verify template list works with built-in templates dir."""
    result = runner.invoke(app, ["template", "list"])
    assert result.exit_code == 0
    assert "templates" in result.output.lower() or "template" in result.output.lower()


def test_template_validate_good() -> None:
    """Verify template validate passes for a valid template."""
    result = runner.invoke(app, ["template", "validate", "templates/sqli-error.yaml"])
    assert result.exit_code == 0
    assert "Passed" in result.output or "valid" in result.output.lower()


def test_template_validate_missing_file() -> None:
    """Verify template validate fails gracefully for missing file."""
    result = runner.invoke(app, ["template", "validate", "nonexistent.yaml"])
    assert result.exit_code == 1


def test_report_help() -> None:
    """Verify report --help works."""
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "INPUT_JSON" in result.output
    assert "--format" in result.output


def test_report_missing_file() -> None:
    """Verify report fails gracefully for missing input file."""
    result = runner.invoke(app, ["report", "nonexistent.json"])
    assert result.exit_code == 1


def test_scan_command_exists() -> None:
    """Verify the scan command is registered and responds to help."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.output.lower() or "TARGET" in result.output


def test_crawl_command_exists() -> None:
    """Verify the crawl command is registered and responds to help."""
    result = runner.invoke(app, ["crawl", "--help"])
    assert result.exit_code == 0
    assert "crawl" in result.output.lower() or "TARGET" in result.output


def test_template_command_exists() -> None:
    """Verify the template command group exists."""
    result = runner.invoke(app, ["template", "--help"])
    assert result.exit_code == 0


def test_report_command_exists() -> None:
    """Verify the report command is registered."""
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
