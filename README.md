# 🛡️ Sentinal-Fuzz

An intelligent, beginner-friendly DAST (Dynamic Application Security Testing) scanner with smart crawling, template-based fuzzing, and a browser UI.

> **Active development:** not ready for production use.

---

## 🚀 Overview

Sentinal-Fuzz makes web application security testing easier by combining:

- endpoint discovery and smart crawling
- template-driven fuzzing for common vulnerability classes
- real-time CLI progress and interactive reports
- an optional FastAPI web dashboard

---

## 🧰 Requirements

- Python 3.11 or newer
- Git (recommended)

> Use `python --version` to verify your interpreter.

---

## ⚡ Quick Start

```bash
cd path/to/gaurd
python -m venv venv
# Windows
venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate
pip install -e ".[web]"
```

Verify installation:

```bash
sentinal-fuzz --help
```

---

## 🔍 Run the CLI Scanner

### Scan the built-in test server

Start the vulnerable built-in server:

```bash
python test_server.py
```

In a second terminal, activate your environment and run:

```bash
sentinal-fuzz scan http://127.0.0.1:8899 --profile quick --output both --output-dir reports
```

### Scan any target

```bash
sentinal-fuzz scan https://example.com --profile standard
```

> ⚠️ Only scan targets you own or have explicit permission to test.

### Useful scan flags

- `--profile` — `quick`, `standard`, `thorough`
- `--output` — `json`, `html`, `both`
- `--output-dir` — report directory
- `--depth` — crawl depth
- `--concurrency` — parallel requests
- `--timeout` — request timeout (seconds)
- `--rate-limit` — max requests per second

---

## 🌐 Run the Web Interface

Start the browser dashboard:

```bash
python -m sentinal_fuzz.web
```

Open:

```text
http://127.0.0.1:8080
```

Optional custom port:

```bash
python -m sentinal_fuzz.web --port 9090
```

---

## 🧪 Practice Targets

### 1. Built-in Test Server

```bash
python test_server.py
sentinal-fuzz scan http://127.0.0.1:8899 --profile quick
```

### 2. OWASP Juice Shop

```bash
docker run -p 3000:3000 bkimminich/juice-shop
```

### 3. DVWA

```bash
docker run -d -p 4280:80 vulnerables/web-dvwa
```

### 4. WebGoat

```bash
docker run -p 8888:8888 webgoat/webgoat
```

---

## 📦 Project Structure

```
gaurd/
├── sentinal_fuzz/
│   ├── core/
│   ├── crawler/
│   ├── fuzzer/
│   ├── analyzer/
│   ├── reporter/
│   ├── cli.py
│   └── web/
│       ├── app.py
│       ├── routes/
│       ├── services/
│       ├── static/
│       └── templates/
├── templates/
├── test_server.py
├── tests/
└── pyproject.toml
```

---

## 📄 License

MIT
