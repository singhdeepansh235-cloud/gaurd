# 🛡️ Sentinal-Fuzz

> An intelligent, beginner-friendly DAST (Dynamic Application Security Testing) scanner with smart crawling, template-based fuzzing, and a beautiful web interface.

**⚠️ Under active development — not yet ready for production use.**

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Quick Start (5 Minutes)](#-quick-start-5-minutes)
- [Running the CLI Scanner](#-running-the-cli-scanner)
- [Running the Web Interface](#-running-the-web-interface)
- [Practice Targets](#-practice-targets)
- [CLI Command Reference](#-cli-command-reference)
- [Project Structure](#-project-structure)
- [License](#-license)

---

## 🛠️ Prerequisites

You need these installed on your computer:

| Tool | Version | Download |
|:--|:--|:--|
| **Python** | 3.11 or higher | [python.org/downloads](https://www.python.org/downloads/) |
| **Git** | Any recent version | [git-scm.com](https://git-scm.com/) |

> **Tip:** To check your Python version, open a terminal and run `python --version` (Windows) or `python3 --version` (macOS/Linux).

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Open Your Terminal

Open **PowerShell** (Windows), **Terminal** (macOS), or your preferred terminal app (Linux).

Navigate to where you downloaded this project:
```bash
cd path/to/Sentinal-Fuzz
```

### Step 2: Create a Virtual Environment

This keeps dependencies isolated from your system Python.

**Windows (PowerShell):**
```powershell
python -m venv venv
```

**macOS / Linux:**
```bash
python3 -m venv venv
```

### Step 3: Activate the Virtual Environment

You must do this **every time** you open a new terminal to work on the project.

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

> 💡 **Getting an error about scripts being disabled?** Run this first:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> Or use Command Prompt instead: `.\venv\Scripts\activate.bat`

**macOS / Linux:**
```bash
source venv/bin/activate
```

You should now see `(venv)` at the start of your terminal prompt.

### Step 4: Install Sentinal-Fuzz

Install the core scanner **and** the web interface dependencies:

```bash
pip install -e ".[web]"
```

> This installs everything you need: the CLI scanner, the web dashboard, and all dependencies.

### Step 5: Verify Installation

```bash
sentinal-fuzz --help
```

You should see a help menu with commands like `scan`, `crawl`, `report`, and `template`.

**That's it! You're ready to scan.** 🎉

---

## 🔍 Running the CLI Scanner

### Method 1: Scan the Built-in Test Server

**Terminal 1 — Start the vulnerable test server:**
```bash
python test_server.py
```
Leave this running. It starts on `http://127.0.0.1:8899`.

**Terminal 2 — Run the scanner:**
```bash
# Activate venv again in this new terminal
# Windows:
.\venv\Scripts\Activate.ps1
# macOS/Linux:
source venv/bin/activate

# Run a quick scan
sentinal-fuzz scan http://127.0.0.1:8899 --profile quick --output both --output-dir reports
```

You'll see a live terminal UI showing:
- 🕷️ Endpoints being discovered
- ⚡ Fuzzing progress
- 🔴 Vulnerabilities found in real-time

### Method 2: Scan Any Target

```bash
# Quick scan (fast, surface-level)
sentinal-fuzz scan https://your-target.com --profile quick

# Standard scan (balanced)
sentinal-fuzz scan https://your-target.com --profile standard

# Thorough scan (deep, comprehensive)
sentinal-fuzz scan https://your-target.com --profile thorough
```

> **⚠️ IMPORTANT:** Only scan websites you own or have explicit permission to test!

### View Reports

After a scan completes, open the HTML report from the `reports/` folder in your browser. It's a self-contained interactive dashboard.

---

## 🌐 Running the Web Interface

The web interface gives you a beautiful dashboard to run and manage scans from your browser.

### Step 1: Start the Web Server

With your virtual environment activated:

```bash
python -m sentinal_fuzz.web
```

You'll see:
```
============================================================
  [*] Sentinal-Fuzz Web Interface
============================================================
  Open in browser: http://127.0.0.1:8080
============================================================
```

### Step 2: Open Your Browser

Go to **http://127.0.0.1:8080**

### Step 3: Run a Scan

1. Enter a target URL in the hero section (e.g., `http://127.0.0.1:8899`)
2. Click **⚡ Scan Now**
3. Watch real-time progress on the Live Scan page
4. View the detailed report when complete

### Optional: Custom Port

```bash
python -m sentinal_fuzz.web --port 9090
```

### Running Both Together

You'll typically want 2 or 3 terminals open:

| Terminal | Command | Purpose |
|:--|:--|:--|
| **1** | `python test_server.py` | Vulnerable test target |
| **2** | `python -m sentinal_fuzz.web` | Web dashboard |
| **3** | *(open browser)* | View the UI at http://127.0.0.1:8080 |

---

## 🎯 Practice Targets

These are open-source apps intentionally built with vulnerabilities for security testing:

### 1. Built-in Test Server (Easiest)
```bash
python test_server.py
# Then scan: http://127.0.0.1:8899
```
Includes: XSS, SQLi, SSTI, SSRF, Path Traversal, Open Redirect, and more.

### 2. OWASP Juice Shop (Recommended)
```bash
docker run -p 3000:3000 bkimminich/juice-shop
# Then scan: http://localhost:3000
```
Modern web app with 100+ security challenges. [GitHub →](https://github.com/juice-shop/juice-shop)

### 3. DVWA (Classic)
```bash
docker run -d -p 4280:80 vulnerables/web-dvwa
# Then scan: http://localhost:4280
```
Classic training target with adjustable difficulty. [GitHub →](https://github.com/digininja/DVWA)

### 4. WebGoat (Educational)
```bash
docker run -p 8888:8888 -p 9090:9090 webgoat/webgoat
# Then scan: http://localhost:8888/WebGoat
```
Interactive security lessons by OWASP. [GitHub →](https://github.com/WebGoat/WebGoat)

---

## 📖 CLI Command Reference

| Command | Description | Example |
|:--|:--|:--|
| `scan` | Run a full security scan | `sentinal-fuzz scan http://target.com` |
| `crawl` | Only crawl (discover endpoints) | `sentinal-fuzz crawl http://target.com` |
| `report` | Generate report from results | `sentinal-fuzz report results.json` |
| `template` | Manage fuzzing templates | `sentinal-fuzz template list` |

### Scan Flags

| Flag | Description | Default |
|:--|:--|:--|
| `--profile` | `quick`, `standard`, or `thorough` | `standard` |
| `--output` | `json`, `html`, or `both` | `both` |
| `--output-dir` | Report output folder | `reports` |
| `--depth` | Crawl depth (1-10) | From profile |
| `--concurrency` | Parallel requests (1-50) | From profile |
| `--timeout` | Request timeout (seconds) | `10` |
| `--rate-limit` | Max requests/sec | `50` |

---

## 📁 Project Structure

```
Sentinal-Fuzz/
├── sentinal_fuzz/          # Main Python package
│   ├── core/               # Scanner engine, config, models
│   ├── crawler/            # Web crawler (HTTP + JS rendering)
│   ├── fuzzer/             # Fuzzing engine + payload templates
│   ├── analyzer/           # Finding classification + CVSS scoring
│   ├── reporter/           # Report generators (HTML, JSON, SARIF)
│   ├── cli.py              # CLI interface (Typer)
│   └── web/                # Web interface
│       ├── app.py          # FastAPI application
│       ├── routes/         # API + page routes
│       ├── services/       # Scan manager + SQLite DB
│       ├── static/         # CSS + JS assets
│       └── templates/      # Jinja2 HTML templates
├── templates/              # Fuzzing template YAML files
├── test_server.py          # Vulnerable test server
├── tests/                  # Test suite
└── pyproject.toml          # Project config + dependencies
```

---

## 📄 License

MIT
"# gaurd" 
