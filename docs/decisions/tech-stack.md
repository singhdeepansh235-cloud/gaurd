# Sentinal-Fuzz — Technology Stack Decision Records

> **Date**: 2026-04-03
> **Status**: All decisions **Accepted**
> **Author**: deep-researcher agent
> **Project**: Sentinal-Fuzz — Intelligent Beginner-Friendly DAST Scanner

---

## Table of Contents

1. [ADR-001: Core Language](#adr-001-core-language--python-asyncio)
2. [ADR-002: Browser Automation](#adr-002-browser-automation--playwright-python)
3. [ADR-003: Local Storage](#adr-003-local-storage--sqlite)
4. [ADR-004: CLI Framework](#adr-004-cli-framework--typer)
5. [ADR-005: HTTP Client](#adr-005-http-client--httpx)
6. [ADR-006: Report Format](#adr-006-report-format--html--json-primary-sarif-secondary)
7. [Summary](#summary)

---

## ADR-001: Core Language — Python (asyncio)

### Status

**Accepted**

### Context

Sentinal-Fuzz needs a core language that supports async crawling, concurrent fuzzing, easy packaging, and most importantly — is approachable for beginner contributors. The two strongest candidates are **Python (asyncio + aiohttp/httpx)** and **Go (goroutines + net/http)**.

### Comparison

| Criteria | Python (asyncio) | Go (goroutines) |
|---|---|---|
| **Concurrency model** | Single-threaded event loop, cooperative multitasking. Excellent for I/O-bound tasks (HTTP requests). GIL limits CPU parallelism but irrelevant for network-heavy DAST scanner. | M:N scheduler with preemptive goroutines. True multi-core parallelism. Lightweight goroutines (2KB stack). |
| **HTTP library maturity** | `httpx` (sync+async, HTTP/2), `aiohttp` (async-native, battle-tested). Rich ecosystem with `requests` as fallback. | `net/http` is production-hardened and part of stdlib. Minimal external deps needed. |
| **Playwright/browser support** | ✅ First-class `playwright-python` with async API. Same API as Node version. Official Microsoft support. | ❌ No official Playwright binding. Must shell out to Node or use `chromedp` (lower-level, no Firefox/WebKit). |
| **Packaging/distribution** | `pip install`, PyPI, Docker. Requires Python runtime on target. `pyinstaller`/`nuitka` for single binary (large). | Single static binary. Cross-compile for any OS/arch. Zero runtime deps. Superior distribution story. |
| **Beginner friendliness** | ✅ Python is the #1 language taught in CS curricula. Vast tutorials, StackOverflow answers. Most security researchers know Python. | Moderate. Statically typed, more boilerplate. Smaller community of security-tool contributors. |
| **Security ecosystem** | Massive: `beautifulsoup4`, `lxml`, `pyyaml`, `jinja2`, `cryptography`, ML/AI libraries for smart detection. | Growing but smaller. Nuclei (Go) proves it works, but fewer parsing/security libs. |
| **Performance** | Good for I/O-bound work. `uvloop` gives 2-4x speedup. Adequate for scanning hundreds of targets concurrently. | Excellent. Compiled to machine code. 10-100x faster for CPU-bound tasks. Scales to thousands of concurrent connections effortlessly. |

### Pros — Python

- ✅ **Beginner-friendly**: lowest barrier to entry for new contributors
- ✅ **Playwright-python**: first-class async browser automation (critical for JS-rendered SPA crawling)
- ✅ **Rich security ecosystem**: BeautifulSoup, lxml, PyYAML, Jinja2, regex, cryptography
- ✅ **Rapid prototyping**: iterate on fuzzing logic and templates faster
- ✅ **AI/ML integration**: if we add smart vulnerability detection later, Python is the natural choice
- ✅ **Type hints**: modern Python (3.11+) with type hints gives Go-like safety without Go's verbosity

### Cons — Python

- ❌ **Performance ceiling**: GIL limits CPU parallelism (mitigated by `multiprocessing` or `uvloop`)
- ❌ **Distribution**: requires Python runtime or bulky PyInstaller binaries
- ❌ **Memory usage**: higher per-connection memory than Go goroutines
- ❌ **Dependency management**: `pip` ecosystem can be fragile (mitigated by `uv`, `poetry`, `pyproject.toml`)

### Decision

**Python 3.11+ with asyncio**.

The scanner is I/O-bound (HTTP requests, not CPU crunching), so Python's async model is sufficient. The killer advantages are:
1. **Playwright-python** is essential for JS-rendered crawling — Go has no equivalent
2. **Beginner friendliness** — this is explicitly a goal of the project
3. **Security ecosystem** — unmatched library support for HTML parsing, YAML templates, and payload generation

### Consequences

- Must use `asyncio` throughout the codebase for concurrency
- Use `uvloop` as event loop for production performance
- Require Python ≥ 3.11 for `TaskGroup`, improved `asyncio`, and better type hints
- Package via PyPI + Docker (not single binary)
- May need `multiprocessing` for CPU-heavy tasks (large-scale response analysis)

---

## ADR-002: Browser Automation — Playwright-Python

### Status

**Accepted**

### Context

The crawler needs to render JavaScript to discover routes in SPAs (React, Angular, Vue). This requires a headless browser automation library. The three candidates are **Playwright-Python**, **Selenium**, and **Puppeteer (Node.js)**.

### Comparison

| Criteria | Playwright-Python | Selenium | Puppeteer (Node) |
|---|---|---|---|
| **Performance** | ✅ Excellent — WebSocket-based DevTools Protocol | ❌ Slower — HTTP-based WebDriver Protocol | ✅ Excellent — WebSocket-based DevTools Protocol |
| **Headless Chrome** | ✅ Full support (Chromium, Firefox, WebKit) | ✅ Supported (Chromium via ChromeDriver) | ✅ Full support (Chromium only) |
| **Async API** | ✅ Native async/await support in Python | ❌ Synchronous by default. Async wrappers exist but are not first-class | ✅ Native async (but Node.js only) |
| **Multi-browser** | ✅ Chromium + Firefox + WebKit | ✅ All browsers via drivers | ❌ Chromium only |
| **Auto-waiting** | ✅ Built-in intelligent auto-wait | ❌ Manual waits required (fragile) | ⚠️ Basic auto-wait |
| **Language fit** | ✅ Python-native (matches our core language) | ✅ Python support | ❌ Node.js only — would require subprocess or microservice |
| **Maintenance** | ✅ Microsoft-backed, very active (weekly releases) | ✅ W3C standard, mature | ✅ Google-backed |
| **Installation** | `pip install playwright && playwright install` | Requires browser drivers (chromedriver, geckodriver) | `npm install puppeteer` |
| **Network interception** | ✅ Built-in route/request interception | ⚠️ Limited, requires proxy | ✅ Built-in |
| **Stealth/anti-detection** | ✅ Good stealth capabilities out of the box | ⚠️ Easily detected by WAFs | ⚠️ Requires `puppeteer-extra-plugin-stealth` |

### Decision

**Playwright-Python**.

- Native async Python API perfectly matches our asyncio architecture
- Multi-browser support (Chromium + Firefox + WebKit) gives broader testing coverage
- Built-in network interception is critical for analyzing requests during crawling
- Auto-waiting eliminates flaky crawl sessions
- Microsoft backing ensures long-term maintenance

### Consequences

- Add `playwright` to dependencies
- Require `playwright install` as a post-install step (downloads browser binaries ~200MB)
- Docker images will be larger due to browser binaries (use `playwright` Docker base images)
- Must handle browser process lifecycle carefully (memory leaks, zombie processes)

---

## ADR-003: Local Storage — SQLite

### Status

**Accepted**

### Context

Scan results (discovered URLs, findings, request/response pairs, metadata) need to be stored locally. We need **zero-setup** for beginners — no database server installation. The candidates are **SQLite**, **flat JSON files**, and **PostgreSQL**.

### Comparison

| Criteria | SQLite | Flat JSON Files | PostgreSQL |
|---|---|---|---|
| **Setup** | ✅ Zero — built into Python stdlib (`sqlite3`) | ✅ Zero — just write files | ❌ Requires server installation and configuration |
| **Querying** | ✅ Full SQL — filter, sort, aggregate, join | ❌ Manual — load entire file into memory, iterate | ✅ Full SQL + advanced features (JSONB, full-text search) |
| **Performance** | ✅ Good for single-user local use | ❌ Degrades with file size (must parse entire file) | ✅ Excellent for multi-user concurrent access |
| **Data integrity** | ✅ ACID compliant | ❌ Corruption risk on crash during write | ✅ ACID compliant |
| **Beginner friendly** | ✅ Python `sqlite3` is stdlib — no pip install needed | ✅ `json.dump()`/`json.load()` — trivial | ❌ Requires learning DB admin |
| **Portability** | ✅ Single `.db` file — copy/share easily | ✅ Single `.json` file — human readable | ❌ Requires running server |
| **Scalability** | ⚠️ Single-writer. Fine for local scans | ❌ Poor — O(n) reads | ✅ Excellent — concurrent read/write |
| **Schema evolution** | ⚠️ Manual migrations (use `alembic` or custom) | ✅ Schema-free | ✅ Robust migration tooling |

### Decision

**SQLite** with JSON export capability.

- Zero setup: Python's `sqlite3` is in the standard library
- SQL querying lets users filter findings by severity, URL, scan date, etc.
- ACID compliance prevents data loss during long-running scans
- Single `.db` file is portable and easy to back up
- We'll add a `--export json` flag for users who want human-readable output

### Consequences

- Use `sqlite3` from stdlib (no additional dependency)
- Design a clean schema for: `scans`, `endpoints`, `findings`, `requests`, `responses`
- Add migration support for schema evolution (simple version table + upgrade scripts)
- Provide `sentinal-fuzz export --format json|csv` for data portability
- Consider `aiosqlite` for async-compatible database access

---

## ADR-004: CLI Framework — Typer

### Status

**Accepted**

### Context

Since we chose Python, we need a CLI framework. The candidates are **Click**, **Typer**, and **argparse** (stdlib).

### Comparison

| Criteria | Typer | Click | argparse |
|---|---|---|---|
| **Boilerplate** | ✅ Minimal — uses type hints | ⚠️ Moderate — decorators for each param | ❌ Verbose — manual argument parsing |
| **Learning curve** | ✅ Very gentle — feels like writing normal Python functions | ⚠️ Moderate — must learn decorator patterns | ❌ Steep for complex CLIs |
| **Auto-completion** | ✅ Built-in shell completion generation | ⚠️ Requires extra setup | ❌ No built-in support |
| **Type safety** | ✅ Native type hints → automatic validation | ⚠️ Types defined in decorators | ❌ Manual type coercion |
| **Rich output** | ✅ Built-in Rich integration (colors, tables, progress bars) | ⚠️ Basic styling, use `click.style()` | ❌ Plain text only |
| **Beginner friendly** | ✅ Code looks like normal Python with type hints | ✅ Explicit decorators are readable | ❌ Verbose and unintuitive |
| **Foundation** | Built on Click (inherits all Click features) | Standalone | Python stdlib |
| **Dependencies** | `typer` + `click` (transitive) | `click` | None |
| **Nested commands** | ✅ Clean subcommand structure | ✅ Click groups | ⚠️ Subparsers (awkward) |

### Decision

**Typer**.

- Minimal boilerplate: define CLI args via function type hints
- Built on Click: inherits all of Click's battle-tested features
- Rich integration: beautiful terminal output with progress bars, colored tables
- Auto-completion: ships with shell completion out of the box
- Aligns with our "beginner-friendly" goal — code reads like standard Python

### Consequences

- Add `typer[all]` to dependencies (includes `rich` and `shellingham`)
- CLI commands defined as `@app.command()` decorated functions
- Use `rich` for all terminal output (tables, progress bars, panels)
- Organize commands: `scan`, `crawl`, `template`, `report`, `config`

---

## ADR-005: HTTP Client — httpx

### Status

**Accepted**

### Context

The fuzzing engine needs an HTTP client for sending payloads to targets. It must support async/await, HTTP/2, connection pooling, and custom headers/proxies. Candidates: **httpx**, **aiohttp**, **requests**.

### Comparison

| Criteria | httpx | aiohttp | requests |
|---|---|---|---|
| **Async support** | ✅ First-class sync + async in same API | ✅ Async-only | ❌ Sync only |
| **HTTP/2** | ✅ Built-in HTTP/2 support | ❌ No HTTP/2 | ❌ No HTTP/2 |
| **API familiarity** | ✅ requests-compatible API | ⚠️ Different API, more verbose | ✅ Gold standard API |
| **Connection pooling** | ✅ `AsyncClient` with connection pooling | ✅ `TCPConnector` with pooling | ✅ `Session` with pooling |
| **Proxy support** | ✅ HTTP/SOCKS proxies | ✅ HTTP/SOCKS proxies | ✅ HTTP/SOCKS proxies |
| **Streaming** | ✅ Request/response streaming | ✅ Streaming | ✅ Streaming |
| **Timeout control** | ✅ Granular (connect, read, write, pool) | ✅ Granular | ⚠️ Basic |
| **Performance (async)** | ✅ High — C-level HTTP parsing | ✅ Highest — optimized C extensions | N/A (sync) |
| **Maintenance** | ✅ Actively maintained (Encode team) | ✅ Actively maintained | ✅ Maintained (slower cadence) |
| **Certificate handling** | ✅ Custom CA, client certs, SSL verification toggle | ✅ Custom SSL context | ✅ Basic cert support |

### Decision

**httpx** as the primary HTTP client.

- **Dual sync/async API**: use `httpx.AsyncClient` for the fuzzing engine, `httpx.Client` for simple utility scripts
- **HTTP/2 support**: critical for testing modern web applications that serve over HTTP/2
- **requests-compatible API**: beginners familiar with `requests` can immediately read httpx code
- **Connection pooling**: `AsyncClient` reuses connections automatically — essential for high-throughput fuzzing
- Keep `aiohttp` as an optional dependency for edge cases where raw async performance matters

### Consequences

- Add `httpx[http2]` to dependencies
- Use `httpx.AsyncClient` as a context manager for connection lifecycle
- Configure custom `Timeout`, `Limits`, and `Proxy` per scan profile
- Write a thin wrapper (`sentinal_fuzz.http.client`) for scanner-specific defaults (user-agent, retry logic, rate limiting)

---

## ADR-006: Report Format — HTML + JSON Primary, SARIF Secondary

### Status

**Accepted** (confirming the proposed approach)

### Context

Scan results need to be exported in formats useful for both humans (security teams, managers) and machines (CI/CD pipelines, vulnerability management platforms).

### Comparison

| Format | Audience | Use Case | Effort |
|---|---|---|---|
| **JSON** | Developers, tools | Machine-readable, API consumption, custom processing | Low — native Python `json` |
| **HTML** | Security teams, managers | Visual report with charts, findings, remediation | Medium — Jinja2 templates |
| **SARIF 2.1.0** | CI/CD, GitHub/GitLab | Industry standard for security tool integration | Medium — structured schema |
| **PDF** | Executives, compliance | Formal reports for audits | High — requires `weasyprint` or similar |
| **CSV** | Data analysts | Spreadsheet analysis, bulk processing | Low — Python `csv` |
| **JUnit XML** | CI/CD pipelines | Test framework integration for pass/fail gates | Low — simple XML |

### Decision

**Confirmed: HTML + JSON as primary, SARIF as secondary.**

#### Primary outputs (always generated):
1. **JSON** — machine-readable findings with full request/response data
2. **HTML** — beautiful standalone report using Jinja2 templates (dark theme, interactive, embeddable charts)

#### Secondary outputs (opt-in via `--format`):
3. **SARIF 2.1.0** — for GitHub Code Scanning, GitLab Security Dashboard, and ASPM tool integration
4. **CSV** — for spreadsheet users and data analysis

#### Future consideration:
5. **PDF** — generated from HTML report (via `weasyprint`)
6. **Markdown** — for embedding in PRs and issues

### Consequences

- Add `jinja2` to dependencies for HTML template rendering
- Design a JSON schema for findings (becomes the internal data model)
- Implement SARIF 2.1.0 mapping (map our findings to SARIF `results`, `locations`, `rules`)
- HTML report should be a single self-contained file (inline CSS/JS) for easy sharing
- Create report templates in `sentinal_fuzz/reporters/templates/`

---

## Summary

| Decision | Choice | Rationale |
|---|---|---|
| **Language** | Python 3.11+ (asyncio) | Beginner-friendly, Playwright support, rich security ecosystem |
| **Browser Automation** | Playwright-Python | Async-native, multi-browser, network interception, auto-waiting |
| **Storage** | SQLite | Zero-setup, ACID compliant, SQL queries, stdlib support |
| **CLI Framework** | Typer | Type-hint driven, minimal boilerplate, Rich integration |
| **HTTP Client** | httpx | Sync+async API, HTTP/2, requests-compatible |
| **Report Format** | HTML + JSON (primary), SARIF (secondary) | Covers humans and machines, CI/CD integration |

### Full Dependency List

```
httpx[http2]      — async HTTP client with HTTP/2
playwright        — headless browser automation
typer[all]        — CLI framework (includes rich, shellingham)
pyyaml            — YAML template parsing
rich              — beautiful terminal output
jinja2            — HTML report templates
aiosqlite         — async SQLite access
uvloop            — high-performance event loop (Linux/macOS)
pydantic          — data validation and settings management
```

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    CLI (Typer)                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Crawler  │→ │ Fuzzer   │→ │ Analyzer/Reporter│  │
│  │(Playwright│  │(httpx +  │  │(SQLite + Jinja2 +│  │
│  │+ httpx)  │  │Templates)│  │ SARIF)           │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │        Storage Layer (SQLite + aiosqlite)    │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │        Template Engine (PyYAML + Pydantic)   │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```
