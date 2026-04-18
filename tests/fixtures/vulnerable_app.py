"""Intentionally vulnerable Flask test server for integration testing.

This server has realistic vulnerabilities that Sentinal-Fuzz should
detect during end-to-end testing:

- **GET /search?q=TERM**  — Reflected XSS (q is echoed unsafely)
- **GET /admin**          — Returns 200 with no security headers
- **POST /login**         — Login form with username/password (SQLi surface)
- **GET /**               — Homepage with links to all pages

Usage::

    # As a standalone server:
    python -m tests.fixtures.vulnerable_app

    # In pytest (see test_integration.py):
    @pytest.fixture
    def vuln_server():
        ...
"""

from __future__ import annotations

import threading
import time
from typing import Any

from flask import Flask, Response, make_response, request

app = Flask(__name__)


# ── Homepage ──────────────────────────────────────────────────────

@app.route("/")
def index() -> str:
    """Homepage with links to all test pages."""
    return """<!DOCTYPE html>
<html>
<head><title>Test App</title></head>
<body>
    <h1>Vulnerable Test Application</h1>
    <ul>
        <li><a href="/search?q=test">Search</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/login">Login</a></li>
        <li><a href="/api/users">API Users</a></li>
    </ul>
</body>
</html>"""


# ── Reflected XSS — GET /search?q=TERM ───────────────────────────

@app.route("/search")
def search() -> str:
    """Reflects the 'q' parameter directly in HTML without escaping.

    This is a classic reflected XSS vulnerability.
    """
    query = request.args.get("q", "")
    # INTENTIONALLY VULNERABLE: no HTML escaping
    return f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: {query}</p>
    <form action="/search" method="GET">
        <input type="text" name="q" value="{query}">
        <button type="submit">Search</button>
    </form>
    <p>No results found for <b>{query}</b></p>
</body>
</html>"""


# ── Admin page — no security headers ─────────────────────────────

@app.route("/admin")
def admin() -> Response:
    """Returns 200 with deliberately missing security headers.

    Missing: CSP, X-Frame-Options, X-Content-Type-Options, HSTS
    """
    resp = make_response("""<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <p>Welcome, administrator.</p>
    <ul>
        <li><a href="/">Home</a></li>
    </ul>
</body>
</html>""")
    # No security headers at all — intentional
    resp.headers.pop("Content-Security-Policy", None)
    resp.headers.pop("X-Frame-Options", None)
    resp.headers.pop("X-Content-Type-Options", None)
    resp.headers.pop("Strict-Transport-Security", None)
    return resp


# ── Login form — SQL injection surface ────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    """Login form with username/password fields.

    GET:  Renders the login form.
    POST: Simulates a login attempt with verbose error on SQL-like input.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Simulate SQL error on injection attempt
        if "'" in username or "'" in password or "--" in username:
            return f"""<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Database Error</h1>
    <p>Error: You have an error in your SQL syntax; check the manual
    that corresponds to your MySQL server version for the right syntax
    to use near '{username}' at line 1</p>
    <p>Query: SELECT * FROM users WHERE username='{username}' AND password='{password}'</p>
</body>
</html>""", 500

        return """<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body>
    <h1>Login Failed</h1>
    <p>Invalid username or password.</p>
    <a href="/login">Try again</a>
</body>
</html>"""

    return """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form action="/login" method="POST">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>"""


# ── API endpoint — JSON response ──────────────────────────────────

@app.route("/api/users")
def api_users() -> tuple[dict[str, Any], int, dict[str, str]]:
    """Simple API endpoint that returns JSON."""
    return {
        "users": [
            {"id": 1, "username": "admin", "email": "admin@example.com"},
            {"id": 2, "username": "user", "email": "user@example.com"},
        ]
    }, 200, {"Content-Type": "application/json"}


# ── Server helpers ────────────────────────────────────────────────

def create_app() -> Flask:
    """Return the Flask app instance."""
    return app


def run_server(host: str = "127.0.0.1", port: int = 0) -> tuple[threading.Thread, int]:
    """Start the server in a background thread.

    Args:
        host: Bind address.
        port: Port (0 = auto-select free port).

    Returns:
        Tuple of (thread, actual_port).
    """
    import socket

    # Find a free port if port=0
    if port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

    def _run() -> None:
        """Run Flask using werkzeug directly for cleaner shutdown."""
        from werkzeug.serving import make_server
        server = make_server(host, port, app, threaded=True)
        server.timeout = 1
        _run._server = server  # type: ignore[attr-defined]
        server.serve_forever()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    # Wait for server to be ready
    for _ in range(50):
        try:
            with socket.create_connection((host, port), timeout=1):
                break
        except OSError:
            time.sleep(0.1)

    return thread, port


if __name__ == "__main__":
    print("Starting vulnerable test server on http://127.0.0.1:8888")
    _, port = run_server(port=8888)
    print(f"Server running on http://127.0.0.1:{port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
