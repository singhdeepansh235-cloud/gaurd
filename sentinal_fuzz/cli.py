"""Sentinal-Fuzz CLI — powered by Typer + Rich.

Entry point for all user-facing commands.  Display logic is delegated
to ``cli_display.py``; configuration merging lives in
``config_loader.py``.  This module only wires arguments to actions.

Usage::

    sentinal-fuzz scan https://example.com
    sentinal-fuzz crawl https://example.com --depth 5
    sentinal-fuzz template list
    sentinal-fuzz report scan_result.json --format html
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import typer
import yaml

import sentinal_fuzz
from sentinal_fuzz.cli_display import (
    ScanProgressDisplay,
    console,
    display_banner,
    display_crawl_results,
    display_error,
    display_finding,
    display_info,
    display_success,
    display_summary,
    display_template_list,
    display_template_validation,
)
from sentinal_fuzz.config_loader import build_config
from sentinal_fuzz.utils.logger import set_global_level

# ────────────────────────────────────────────────────────────────────
#  App & sub-apps
# ────────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="sentinal-fuzz",
    help="🛡️  Sentinal-Fuzz — Intelligent DAST Scanner",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
    pretty_exceptions_enable=False,   # we handle errors ourselves
)

template_app = typer.Typer(
    name="template",
    help="📋 Manage fuzzing templates.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(template_app, name="template")


# ────────────────────────────────────────────────────────────────────
#  Global state set by the main callback
# ────────────────────────────────────────────────────────────────────

class _GlobalState:
    config_file: str | None = None
    verbose: bool = False
    quiet: bool = False


_state = _GlobalState()


# ────────────────────────────────────────────────────────────────────
#  Version callback
# ────────────────────────────────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        console.print(
            f"[bold cyan]sentinal-fuzz[/bold cyan] version "
            f"[green]{sentinal_fuzz.__version__}[/green]"
        )
        raise typer.Exit()


# ────────────────────────────────────────────────────────────────────
#  Main callback (global options)
# ────────────────────────────────────────────────────────────────────

@app.callback()
def main(
    config: Optional[str] = typer.Option(
        None, "--config", "-c",
        help="Path to a YAML configuration file.",
        envvar="SENTINAL_CONFIG",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug-level output.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress all output except findings.",
    ),
    version: Optional[bool] = typer.Option(
        None, "--version",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """🛡️  Sentinal-Fuzz — Intelligent DAST Scanner."""
    _state.config_file = config
    _state.verbose = verbose
    _state.quiet = quiet

    # Adjust log level globally
    if verbose:
        set_global_level(logging.DEBUG)
    elif quiet:
        set_global_level(logging.WARNING)


# ────────────────────────────────────────────────────────────────────
#  COMMAND: scan
# ────────────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Target URL to scan (e.g. https://example.com).",
    ),
    depth: int = typer.Option(
        3, "--depth", "-d", min=1,
        help="Maximum crawl depth.",
    ),
    concurrency: int = typer.Option(
        20, "--concurrency", min=1,
        help="Number of parallel HTTP requests.",
    ),
    profile: str = typer.Option(
        "standard", "--profile", "-p",
        help="Scan intensity profile: [bold]quick[/bold] | [bold]standard[/bold] | [bold]thorough[/bold].",
    ),
    output: str = typer.Option(
        "both", "--output", "-O",
        help="Report format: [bold]json[/bold] | [bold]html[/bold] | [bold]both[/bold].",
    ),
    output_dir: str = typer.Option(
        "reports", "--output-dir", "-o",
        help="Directory to save reports.",
    ),
    templates: Optional[str] = typer.Option(
        None, "--templates",
        help="Comma-separated template tags (default: all).",
    ),
    auth_cookie: Optional[str] = typer.Option(
        None, "--auth-cookie",
        help="Session cookie for authenticated scanning.",
        envvar="SENTINAL_AUTH_COOKIE",
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy",
        help="HTTP/SOCKS5 proxy URL (e.g. http://127.0.0.1:8080).",
        envvar="SENTINAL_PROXY",
    ),
    rate_limit: int = typer.Option(
        50, "--rate-limit", min=0,
        help="Max requests per second (0 = unlimited).",
    ),
    timeout: int = typer.Option(
        10, "--timeout", min=1,
        help="HTTP request timeout in seconds.",
    ),
    exclude_path: Optional[list[str]] = typer.Option(
        None, "--exclude-path",
        help="Regex pattern to exclude URLs (repeatable).",
    ),
) -> None:
    """🎯 Run a full DAST scan against the target URL.

    Discovers endpoints, fuzzes them with security payloads, and reports
    any vulnerabilities found.
    """
    try:
        # Build merged config
        cli_overrides = {
            "depth": depth,
            "concurrency": concurrency,
            "profile": profile,
            "output": output,
            "output_dir": output_dir,
            "templates": templates,
            "auth_cookie": auth_cookie,
            "proxy": proxy,
            "rate_limit": rate_limit,
            "timeout": timeout,
            "exclude_path": exclude_path,
        }
        config = build_config(
            config_file=_state.config_file,
            cli_overrides=cli_overrides,
            target=target,
        )
        config.verbose = _state.verbose

    except (ValueError, FileNotFoundError) as exc:
        display_error(str(exc))
        raise typer.Exit(code=1) from exc

    # Print banner unless --quiet
    if not _state.quiet:
        display_banner(sentinal_fuzz.__version__)

    # Set up progress display with scan metadata
    progress = ScanProgressDisplay(
        target=target,
        profile=profile,
        version=sentinal_fuzz.__version__,
    )

    async def _run_scan() -> None:
        from sentinal_fuzz.core.scanner import Scanner

        scanner = Scanner(config=config)

        # ── Register EventBus handlers for live TUI updates ──────
        _forms_count = 0
        _api_count = 0

        def _on_url_found(url: str = "", **_kw: object) -> None:
            nonlocal _forms_count, _api_count
            # Heuristic: track forms and API endpoints
            if "/api/" in url or url.endswith((".json", ".xml")):
                _api_count += 1
            progress.update_crawl_stats(
                urls_found=progress.urls_found + 1,
                apis=_api_count,
                current_url=url,
            )

        def _on_crawl_complete(endpoints: object = None, **_kw: object) -> None:
            if endpoints is not None:
                ep_list = endpoints if isinstance(endpoints, list) else []
                # Count forms across endpoints
                forms = sum(
                    len(getattr(ep, "forms", []))
                    for ep in ep_list
                    if hasattr(ep, "forms")
                )
                apis = sum(
                    1 for ep in ep_list
                    if getattr(ep, "is_api", False)
                )
                progress.update_crawl_stats(
                    urls_found=len(ep_list),
                    forms=forms,
                    apis=apis,
                )
                progress.update_fuzz_stats(total=len(ep_list))

        def _on_finding(finding: object = None, **_kw: object) -> None:
            from sentinal_fuzz.core.models import Finding as FindingModel
            if finding is not None and isinstance(finding, FindingModel):
                progress.add_finding(finding)

        def _on_stage_changed(stage: str = "", **_kw: object) -> None:
            progress.set_stage(stage)

        def _on_fuzz_progress(
            endpoints_tested: int = 0,
            endpoints_total: int = 0,
            requests_sent: int = 0,
            current_url: str = "",
            **_kw: object,
        ) -> None:
            elapsed = time.monotonic() - progress._start_time
            rps = requests_sent / max(elapsed, 0.001)
            # ETA estimate
            if endpoints_tested > 0 and endpoints_total > endpoints_tested:
                per_endpoint = elapsed / endpoints_tested
                remaining = endpoints_total - endpoints_tested
                eta = per_endpoint * remaining
            else:
                eta = None
            progress.update_fuzz_stats(
                tested=endpoints_tested,
                total=endpoints_total,
                requests_sent=requests_sent,
                req_per_sec=rps,
                eta_seconds=eta,
            )

        scanner.event_bus.on("url_found", _on_url_found)
        scanner.event_bus.on("crawl_complete", _on_crawl_complete)
        scanner.event_bus.on("finding", _on_finding)
        scanner.event_bus.on("stage_changed", _on_stage_changed)
        scanner.event_bus.on("fuzz_progress", _on_fuzz_progress)

        # Also keep legacy hooks wired for backward compat
        scanner.on_url_found.append(lambda url: _on_url_found(url=url))
        scanner.on_finding.append(lambda f: _on_finding(finding=f))

        if not _state.quiet:
            progress.start()

        try:
            result = await scanner.run()

            # Update final counts on the live display
            progress.update_crawl_stats(urls_found=len(result.endpoints))
            progress.update_fuzz_stats(
                tested=len(result.endpoints),
                total=len(result.endpoints),
                requests_sent=result.stats.total_requests,
                req_per_sec=result.stats.requests_per_second,
            )
            progress.update_requests(result.stats.total_requests)

        finally:
            # Build an AnalysisReport for the final summary
            analysis_report = None
            if not _state.quiet:
                try:
                    from sentinal_fuzz.analyzer.aggregator import (
                        AnalysisReport,
                        aggregate,
                    )
                    from sentinal_fuzz.analyzer.classifier import VulnClassifier

                    classifier = VulnClassifier()
                    enriched = [classifier.classify(f) for f in result.findings]
                    analysis_report = aggregate(
                        enriched,
                        total_endpoints=len(result.endpoints),
                    )
                except Exception:
                    # Fallback: build a minimal report from ScanResult stats
                    from sentinal_fuzz.analyzer.aggregator import AnalysisReport

                    analysis_report = AnalysisReport(
                        total_findings=len(result.findings),
                        by_severity={
                            "Critical": result.stats.findings_by_severity.get("critical", 0),
                            "High": result.stats.findings_by_severity.get("high", 0),
                            "Medium": result.stats.findings_by_severity.get("medium", 0),
                            "Low": result.stats.findings_by_severity.get("low", 0),
                            "Info": result.stats.findings_by_severity.get("info", 0),
                        },
                        unique_endpoints_affected=len(result.endpoints),
                    )

            progress.stop(summary=analysis_report)

        # Also print the detailed display_summary (all findings table)
        if not _state.quiet:
            display_summary(result)

        # Save JSON result
        json_path = Path(config.output_dir) / f"scan_{result.scan_id}.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        if not _state.quiet:
            display_success(f"Full results saved to [bold]{json_path}[/bold]")

            # Print report path
            report_dir = Path(config.output_dir).resolve()
            display_info(f"Reports directory: [bold]{report_dir}[/bold]")

        # Exit with non-zero code if critical/high findings
        if result.critical_count > 0 or result.high_count > 0:
            raise typer.Exit(code=2)

    try:
        asyncio.run(_run_scan())
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        display_info("Scan interrupted by user.")
        raise typer.Exit(code=130)
    except Exception as exc:
        display_error(
            f"Scan failed: {exc}",
            hint="Run with --verbose for full debug output.",
        )
        if _state.verbose:
            console.print_exception()
        raise typer.Exit(code=1) from exc


# ────────────────────────────────────────────────────────────────────
#  COMMAND: crawl
# ────────────────────────────────────────────────────────────────────

@app.command()
def crawl(
    target: str = typer.Argument(
        ...,
        help="Target URL to crawl.",
    ),
    depth: int = typer.Option(
        3, "--depth", "-d", min=1,
        help="Maximum crawl depth.",
    ),
    output: str = typer.Option(
        "crawl_results.json", "--output", "-o",
        help="JSON file path for discovered endpoints.",
    ),
    js: bool = typer.Option(
        False, "--js/--no-js",
        help="Enable JavaScript rendering via Playwright.",
    ),
) -> None:
    """🕷️  Crawl a target URL and discover endpoints.

    Outputs a JSON file containing all discovered endpoints with their
    parameters, forms, and headers.
    """
    if not _state.quiet:
        display_banner(sentinal_fuzz.__version__)

    try:
        config = build_config(
            config_file=_state.config_file,
            cli_overrides={
                "depth": depth,
                "js": js,
            },
            target=target,
        )
    except (ValueError, FileNotFoundError) as exc:
        display_error(str(exc))
        raise typer.Exit(code=1) from exc

    async def _run_crawl() -> None:
        from sentinal_fuzz.core.models import Endpoint
        from sentinal_fuzz.core.scanner import Scanner

        scanner = Scanner(config=config)

        if not _state.quiet:
            display_info(f"Crawling [bold]{target}[/bold] (depth={depth}, js={js})")

        async with __import__("sentinal_fuzz.utils.http", fromlist=["HttpClient"]).HttpClient(
            timeout=config.timeout,
            proxy=config.proxy,
            follow_redirects=config.follow_redirects,
        ) as client:
            scanner.http_client = client
            endpoints = await scanner._crawl()

        # Serialize endpoints
        endpoints_data = [
            {
                "url": ep.url,
                "method": ep.method,
                "params": ep.params,
                "headers": ep.headers,
                "forms": ep.forms,
                "cookies": ep.cookies,
                "source": ep.source,
            }
            for ep in endpoints
        ]

        # Write JSON output
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target": target,
                    "depth": depth,
                    "js_rendering": js,
                    "endpoints_count": len(endpoints_data),
                    "endpoints": endpoints_data,
                },
                f,
                indent=2,
            )

        if not _state.quiet:
            display_crawl_results(endpoints_data, str(out_path))

    try:
        asyncio.run(_run_crawl())
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        display_info("Crawl interrupted by user.")
        raise typer.Exit(code=130)
    except Exception as exc:
        display_error(
            f"Crawl failed: {exc}",
            hint="Run with --verbose for full debug output.",
        )
        if _state.verbose:
            console.print_exception()
        raise typer.Exit(code=1) from exc


# ────────────────────────────────────────────────────────────────────
#  COMMAND: template list
# ────────────────────────────────────────────────────────────────────

@template_app.command("list")
def template_list(
    path: str = typer.Option(
        "templates", "--path", "-p",
        help="Directory containing YAML template files.",
    ),
) -> None:
    """📋 List all available fuzzing templates with their tags."""
    templates_dir = Path(path)
    if not templates_dir.is_dir():
        display_error(
            f"Templates directory not found: {templates_dir}",
            hint="Use --path to specify the templates directory.",
        )
        raise typer.Exit(code=1)

    templates: list[dict[str, object]] = []
    for yaml_file in sorted(templates_dir.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "id" in data:
                templates.append(data)
        except yaml.YAMLError as exc:
            display_error(f"Failed to parse {yaml_file.name}: {exc}")

    if not templates:
        display_info("No templates found.")
        return

    display_template_list(templates)
    display_info(f"Found [bold]{len(templates)}[/bold] templates in [bold]{templates_dir}[/bold]")


# ────────────────────────────────────────────────────────────────────
#  COMMAND: template validate
# ────────────────────────────────────────────────────────────────────

@template_app.command("validate")
def template_validate(
    file: str = typer.Argument(
        ...,
        help="Path to the YAML template file to validate.",
    ),
) -> None:
    """✅ Validate a YAML template file against the schema."""
    filepath = Path(file)
    if not filepath.exists():
        display_error(f"File not found: {filepath}")
        raise typer.Exit(code=1)

    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        display_error(f"YAML parse error: {exc}")
        raise typer.Exit(code=1) from exc

    errors = _validate_template(data)
    display_template_validation(str(filepath), errors)

    if errors:
        raise typer.Exit(code=1)


def _validate_template(data: object) -> list[str]:
    """Validate template structure and return a list of error strings.

    Supports two template formats:
    - **Flat format** (Sentinal-Fuzz native): top-level `name`, `severity`,
      `payloads`, `matchers` fields.
    - **Nuclei-style format**: nested `info` and `requests` sections.
    """
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["Template must be a YAML mapping (dict)."]

    # Required in both formats
    if "id" not in data:
        errors.append("Missing required field: 'id'")

    # ── Detect format ──────────────────────────────────────────────
    is_flat = "name" in data or "severity" in data or "matchers" in data

    if is_flat:
        # ── Flat format validation ─────────────────────────────────
        if "name" not in data:
            errors.append("Missing required field: 'name'")
        if "severity" not in data:
            errors.append("Missing required field: 'severity'")
        elif data["severity"] not in ("critical", "high", "medium", "low", "info"):
            errors.append(
                f"Invalid severity: '{data['severity']}'. "
                "Must be one of: critical, high, medium, low, info"
            )
        if "tags" in data and not isinstance(data["tags"], list):
            errors.append("'tags' must be a list.")
        if "matchers" not in data:
            errors.append("Missing required field: 'matchers'")
        elif not isinstance(data["matchers"], list):
            errors.append("'matchers' must be a list.")
        # payloads can be a list or a string (file path)
        if "payloads" in data:
            if not isinstance(data["payloads"], (list, str)):
                errors.append("'payloads' must be a list or a file path string.")
    else:
        # ── Nuclei-style format validation ─────────────────────────
        if "info" not in data:
            errors.append("Missing required field: 'info'")
        else:
            info = data["info"]
            if not isinstance(info, dict):
                errors.append("'info' must be a mapping.")
            else:
                if "name" not in info:
                    errors.append("Missing required field: 'info.name'")
                if "severity" not in info:
                    errors.append("Missing required field: 'info.severity'")
                elif info["severity"] not in ("critical", "high", "medium", "low", "info"):
                    errors.append(
                        f"Invalid severity: '{info['severity']}'. "
                        "Must be one of: critical, high, medium, low, info"
                    )
                if "tags" in info and not isinstance(info["tags"], list):
                    errors.append("'info.tags' must be a list.")

        if "requests" not in data:
            errors.append("Missing required field: 'requests'")
        else:
            requests = data["requests"]
            if not isinstance(requests, list) or len(requests) == 0:
                errors.append("'requests' must be a non-empty list.")
            else:
                for idx, req in enumerate(requests):
                    if not isinstance(req, dict):
                        errors.append(f"requests[{idx}] must be a mapping.")
                        continue
                    if "payloads" not in req:
                        errors.append(f"requests[{idx}]: missing 'payloads'.")
                    elif not isinstance(req["payloads"], list):
                        errors.append(f"requests[{idx}]: 'payloads' must be a list.")
                    if "matchers" not in req:
                        errors.append(f"requests[{idx}]: missing 'matchers'.")

    return errors


# ────────────────────────────────────────────────────────────────────
#  COMMAND: template new
# ────────────────────────────────────────────────────────────────────

@template_app.command("new")
def template_new(
    name: str = typer.Argument(
        ...,
        help="Name/ID for the new template (e.g. 'sqli-blind-time').",
    ),
    output_dir: str = typer.Option(
        "templates", "--output-dir", "-o",
        help="Directory to create the template in.",
    ),
) -> None:
    """🆕 Scaffold a new fuzzing template interactively."""
    # Prompt for metadata
    display_info(f"Creating new template: [bold]{name}[/bold]")

    severity = typer.prompt(
        "Severity (critical/high/medium/low/info)",
        default="medium",
    )
    description = typer.prompt(
        "Description",
        default=f"Custom fuzzing template: {name}",
    )
    tags_input = typer.prompt(
        "Tags (comma-separated)",
        default="custom",
    )
    tags = [t.strip() for t in tags_input.split(",") if t.strip()]

    # Build scaffold YAML
    scaffold = {
        "id": name,
        "info": {
            "name": name.replace("-", " ").replace("_", " ").title(),
            "severity": severity,
            "tags": tags,
            "description": description,
            "references": [],
        },
        "requests": [
            {
                "method": "GET",
                "path": "{{BaseURL}}{{Path}}",
                "params": {"{{Parameter}}": "{{Payload}}"},
                "payloads": [
                    "PAYLOAD_1",
                    "PAYLOAD_2",
                ],
                "matchers": [
                    {
                        "type": "word",
                        "part": "body",
                        "words": ["EXPECTED_PATTERN"],
                        "condition": "or",
                    }
                ],
            }
        ],
    }

    # Write file
    out_path = Path(output_dir) / f"{name}.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"# Fuzzing template: {name}\n")
        f.write(f"# Generated by sentinal-fuzz template new\n\n")
        yaml.dump(scaffold, f, default_flow_style=False, sort_keys=False)

    display_success(f"Template created: [bold]{out_path}[/bold]")
    display_info("Edit the payloads and matchers to customize the template.")


# ────────────────────────────────────────────────────────────────────
#  COMMAND: report
# ────────────────────────────────────────────────────────────────────

@app.command()
def report(
    input_json: str = typer.Argument(
        ...,
        help="Path to a JSON scan result file.",
    ),
    format: str = typer.Option(
        "html", "--format", "-f",
        help="Report format: [bold]html[/bold] | [bold]json[/bold] | [bold]sarif[/bold].",
    ),
    output: str = typer.Option(
        "reports", "--output", "-o",
        help="Output directory for the generated report.",
    ),
) -> None:
    """📊 Re-generate a report from a previously saved JSON scan result."""
    input_path = Path(input_json)
    if not input_path.exists():
        display_error(
            f"Input file not found: {input_path}",
            hint="Provide a valid path to a scan result JSON file.",
        )
        raise typer.Exit(code=1)

    try:
        with open(input_path, encoding="utf-8") as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as exc:
        display_error(f"Invalid JSON: {exc}")
        raise typer.Exit(code=1) from exc

    if not _state.quiet:
        display_banner(sentinal_fuzz.__version__)

    # Build output directory
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_id = scan_data.get("scan_id", "unknown")
    target = scan_data.get("target", "unknown")

    if format == "json":
        out_file = out_dir / f"report_{scan_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2)
        display_success(f"JSON report saved to [bold]{out_file}[/bold]")

    elif format == "html":
        _generate_html_report(scan_data, out_dir, scan_id)

    elif format == "sarif":
        _generate_sarif_report(scan_data, out_dir, scan_id)

    else:
        display_error(
            f"Unsupported format: {format}",
            hint="Supported formats: html, json, sarif",
        )
        raise typer.Exit(code=1)


def _generate_html_report(
    scan_data: dict, out_dir: Path, scan_id: str
) -> None:
    """Generate an HTML report from scan data using Jinja2."""
    try:
        import jinja2
    except ImportError:
        display_error(
            "Jinja2 is required for HTML report generation.",
            hint="Install it with: pip install jinja2",
        )
        raise typer.Exit(code=1)

    findings = scan_data.get("findings", [])
    summary = scan_data.get("summary", {})

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinal-Fuzz Report — {{ target }}</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --border: #334155;
                --text: #e2e8f0; --accent: #38bdf8; --red: #ef4444;
                --orange: #f97316; --yellow: #eab308; --blue: #3b82f6;
                --green: #22c55e; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', 'Segoe UI', sans-serif; background: var(--bg);
               color: var(--text); line-height: 1.6; padding: 2rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        h1 { color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; margin-bottom: 2rem; }
        .card { background: var(--card); border: 1px solid var(--border);
                border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                 gap: 1rem; margin-bottom: 2rem; }
        .stat-box { background: var(--card); border: 1px solid var(--border);
                    border-radius: 8px; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }
        .sev-critical { color: var(--red); border-left: 4px solid var(--red); }
        .sev-high { color: var(--orange); border-left: 4px solid var(--orange); }
        .sev-medium { color: var(--yellow); border-left: 4px solid var(--yellow); }
        .sev-low { color: var(--blue); border-left: 4px solid var(--blue); }
        .sev-info { color: #94a3b8; border-left: 4px solid #64748b; }
        .finding { margin-bottom: 1rem; padding-left: 1rem; }
        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .finding-meta { color: #94a3b8; font-size: 0.85rem; margin-top: 0.3rem; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px;
               font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .tag-critical { background: rgba(239,68,68,0.2); color: var(--red); }
        .tag-high { background: rgba(249,115,22,0.2); color: var(--orange); }
        .tag-medium { background: rgba(234,179,8,0.2); color: var(--yellow); }
        .tag-low { background: rgba(59,130,246,0.2); color: var(--blue); }
        .tag-info { background: rgba(100,116,139,0.2); color: #94a3b8; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--accent); font-size: 0.85rem; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sentinal-Fuzz Scan Report</h1>
        <p class="subtitle">Target: {{ target }} &bull; Scan ID: {{ scan_id }}</p>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-value" style="color: var(--accent);">{{ endpoints }}</div>
                <div class="stat-label">Endpoints</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: var(--red);">{{ critical }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: var(--orange);">{{ high }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: var(--yellow);">{{ medium }}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        {% if findings %}
        <div class="card">
            <h2 style="margin-bottom: 1rem;">Findings</h2>
            <table>
                <thead>
                    <tr><th>#</th><th>Severity</th><th>Title</th><th>URL</th><th>CWE</th></tr>
                </thead>
                <tbody>
                {% for f in findings %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td><span class="tag tag-{{ f.severity }}">{{ f.severity }}</span></td>
                        <td>{{ f.title }}</td>
                        <td style="font-size: 0.85rem; color: #94a3b8;">{{ f.url }}</td>
                        <td>{{ f.cwe or '—' }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        {% for f in findings %}
        <div class="card finding sev-{{ f.severity }}">
            <div class="finding-title">
                <span class="tag tag-{{ f.severity }}">{{ f.severity }}</span>
                {{ f.title }}
            </div>
            <div class="finding-meta">
                URL: {{ f.url }}
                {% if f.parameter %}&bull; Parameter: {{ f.parameter }}{% endif %}
                {% if f.cwe %}&bull; {{ f.cwe }}{% endif %}
            </div>
            {% if f.evidence %}
            <p style="margin-top: 0.5rem; font-size: 0.9rem;">{{ f.evidence }}</p>
            {% endif %}
            {% if f.remediation %}
            <p style="margin-top: 0.5rem; color: var(--green); font-size: 0.9rem;">
                💡 {{ f.remediation }}
            </p>
            {% endif %}
        </div>
        {% endfor %}

        {% else %}
        <div class="card" style="text-align: center; color: var(--green);">
            <h2>✅ No vulnerabilities found</h2>
        </div>
        {% endif %}

        <p style="text-align: center; color: #64748b; margin-top: 2rem; font-size: 0.8rem;">
            Generated by Sentinal-Fuzz v{{ version }}
        </p>
    </div>
</body>
</html>"""

    env = jinja2.Environment(autoescape=True)
    tmpl = env.from_string(html_template)
    html = tmpl.render(
        target=scan_data.get("target", "unknown"),
        scan_id=scan_id,
        endpoints=summary.get("endpoints_found", 0),
        critical=summary.get("critical", 0),
        high=summary.get("high", 0),
        medium=sum(
            1 for f in findings if f.get("severity") == "medium"
        ),
        total_findings=summary.get("total_findings", len(findings)),
        findings=findings,
        version=sentinal_fuzz.__version__,
    )

    out_file = out_dir / f"report_{scan_id}.html"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)

    display_success(f"HTML report saved to [bold]{out_file}[/bold]")


def _generate_sarif_report(
    scan_data: dict, out_dir: Path, scan_id: str
) -> None:
    """Generate a SARIF 2.1.0 report from scan data."""
    findings = scan_data.get("findings", [])

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinal-Fuzz",
                        "version": sentinal_fuzz.__version__,
                        "informationUri": "https://github.com/sentinal-fuzz/sentinal-fuzz",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rules_seen: set[str] = set()
    run = sarif["runs"][0]

    for finding in findings:
        rule_id = finding.get("cwe", finding.get("title", "unknown"))

        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append(  # type: ignore[union-attr]
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("title", "")},
                }
            )

        sev_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        run["results"].append(  # type: ignore[union-attr]
            {
                "ruleId": rule_id,
                "level": sev_map.get(finding.get("severity", "info"), "note"),
                "message": {
                    "text": finding.get("evidence", finding.get("title", "")),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("url", ""),
                            }
                        }
                    }
                ],
            }
        )

    out_file = out_dir / f"report_{scan_id}.sarif"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    display_success(f"SARIF report saved to [bold]{out_file}[/bold]")


# ────────────────────────────────────────────────────────────────────
#  __main__ support
# ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
