"""Intentionally vulnerable test server for Sentinal-Fuzz testing.

This server exposes several common vulnerability patterns so you can
see the scanner in action.  **Never deploy this in production.**

Run:
    python test_server.py

Then in another terminal:
    sentinal-fuzz scan http://localhost:8899 --profile quick
"""

from aiohttp import web
import json

# ── Routes ────────────────────────────────────────────────────────

async def index(request: web.Request) -> web.Response:
    html = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Test App</title></head>
<body>
  <h1>Sentinal-Fuzz Test Application</h1>
  <nav>
    <ul>
      <li><a href="/search?q=hello">Search</a></li>
      <li><a href="/login">Login</a></li>
      <li><a href="/api/users">API: Users</a></li>
      <li><a href="/profile?user=admin">Profile</a></li>
      <li><a href="/redirect?url=https://example.com">Redirect</a></li>
      <li><a href="/file?name=readme.txt">File Viewer</a></li>
      <li><a href="/template?name=guest">Template</a></li>
      <li><a href="/fetch?url=http://localhost">Fetch URL</a></li>
      <li><a href="/debug">Debug Info</a></li>
    </ul>
  </nav>
  <form action="/search" method="GET">
    <input type="text" name="q" placeholder="Search...">
    <button type="submit">Search</button>
  </form>
  <form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
</body>
</html>"""
    return web.Response(text=html, content_type="text/html")


async def search(request: web.Request) -> web.Response:
    """XSS: reflects the query parameter directly into HTML."""
    query = request.query.get("q", "")
    # VULNERABLE: No escaping — reflected XSS
    html = f"""<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
  <h1>Search Results for: {query}</h1>
  <p>No results found for "<b>{query}</b>".</p>
  <a href="/">Back</a>
</body></html>"""
    return web.Response(text=html, content_type="text/html")


async def login(request: web.Request) -> web.Response:
    if request.method == "POST":
        data = await request.post()
        username = data.get("username", "")
        # VULNERABLE: SQL error message in response (simulated)
        if "'" in username:
            return web.Response(
                text=f"""<html><body>
<h1>Error</h1>
<p>Database error: You have an error in your SQL syntax near '{username}'
   at line 1: SELECT * FROM users WHERE username='{username}'</p>
<p>MySQL server version: 8.0.32</p>
</body></html>""",
                content_type="text/html",
                status=500,
            )
        return web.Response(
            text="<html><body><h1>Login Failed</h1><p>Invalid credentials.</p></body></html>",
            content_type="text/html",
        )
    # GET — show login form
    return web.Response(
        text="""<html><body>
<h1>Login</h1>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form></body></html>""",
        content_type="text/html",
    )


async def api_users(request: web.Request) -> web.Response:
    """API endpoint with sensitive data exposure."""
    users = [
        {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "api_key": "sk-proj-1234567890abcdef",
            "role": "admin",
        },
        {
            "id": 2,
            "username": "user1",
            "email": "user1@example.com",
            "password_hash": "e99a18c428cb38d5f260853678922e03",
            "api_key": "sk-proj-abcdef1234567890",
            "role": "user",
        },
    ]
    return web.json_response(users)


async def profile(request: web.Request) -> web.Response:
    """Profile page with query parameter — injectable."""
    user = request.query.get("user", "guest")
    html = f"""<!DOCTYPE html>
<html><head><title>Profile - {user}</title></head>
<body>
  <h1>Profile: {user}</h1>
  <p>Welcome back, {user}!</p>
  <a href="/">Back</a>
</body></html>"""
    return web.Response(text=html, content_type="text/html")


async def redirect_page(request: web.Request) -> web.Response:
    """Open redirect — redirects to any user-supplied URL."""
    url = request.query.get("url", "/")
    # VULNERABLE: No validation on redirect target
    raise web.HTTPFound(location=url)


async def file_viewer(request: web.Request) -> web.Response:
    """Path traversal — uses filename directly."""
    name = request.query.get("name", "readme.txt")
    # VULNERABLE: Path traversal (simulated response)
    if ".." in name or name.startswith("/"):
        # Simulate that path traversal "worked"
        return web.Response(
            text=f"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            content_type="text/plain",
        )
    return web.Response(
        text=f"<html><body><h1>File: {name}</h1><pre>File content here.</pre></body></html>",
        content_type="text/html",
    )


async def template_page(request: web.Request) -> web.Response:
    """SSTI — evaluates template expression (simulated)."""
    name = request.query.get("name", "guest")
    # VULNERABLE: If input contains template syntax, simulate evaluation
    if "{{" in name and "}}" in name:
        # Simulate SSTI: {{7*7}} → 49
        try:
            expr = name.split("{{")[1].split("}}")[0].strip()
            result = eval(expr)  # DANGEROUS — intentional for testing
            return web.Response(
                text=f"<html><body><h1>Hello {result}</h1></body></html>",
                content_type="text/html",
            )
        except Exception:
            pass
    return web.Response(
        text=f"<html><body><h1>Hello {name}</h1><a href='/'>Back</a></body></html>",
        content_type="text/html",
    )


async def fetch_url(request: web.Request) -> web.Response:
    """SSRF — fetches any user-supplied URL (simulated)."""
    url = request.query.get("url", "")
    if not url:
        return web.Response(
            text="<html><body><h1>Fetch URL</h1><p>Provide ?url= parameter</p></body></html>",
            content_type="text/html",
        )
    # VULNERABLE: SSRF — would fetch arbitrary URLs in a real app
    return web.Response(
        text=f"<html><body><h1>Fetched URL</h1><p>Response from: {url}</p><pre>...</pre></body></html>",
        content_type="text/html",
    )


async def debug_page(request: web.Request) -> web.Response:
    """Debug info page — sensitive information exposure."""
    import sys
    import os

    debug_info = {
        "python_version": sys.version,
        "platform": sys.platform,
        "cwd": os.getcwd(),
        "env": {
            "PATH": os.environ.get("PATH", ""),
            "DATABASE_URL": "postgresql://admin:s3cretP@ss@db.internal:5432/myapp",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SECRET_KEY": "super-secret-django-key-12345",
        },
        "debug": True,
        "stack_trace": "Traceback (most recent call last):\n  File 'app.py', line 42\n    ...",
    }
    return web.json_response(debug_info)


# ── Missing security headers (intentional) ───────────────────────

@web.middleware
async def no_security_headers(request: web.Request, handler):
    """Intentionally omit security headers."""
    response = await handler(request)
    # VULNERABLE: No security headers set
    # Missing: X-Frame-Options, X-Content-Type-Options,
    # Content-Security-Policy, Strict-Transport-Security
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    return response


# ── App setup ─────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application(middlewares=[no_security_headers])
    app.router.add_get("/", index)
    app.router.add_get("/search", search)
    app.router.add_route("*", "/login", login)
    app.router.add_get("/api/users", api_users)
    app.router.add_get("/profile", profile)
    app.router.add_get("/redirect", redirect_page)
    app.router.add_get("/file", file_viewer)
    app.router.add_get("/template", template_page)
    app.router.add_get("/fetch", fetch_url)
    app.router.add_get("/debug", debug_page)
    return app


if __name__ == "__main__":
    print("=" * 60)
    print("  [TARGET] Sentinal-Fuzz Vulnerable Test Server")
    print("  [WARNING] DO NOT use in production!")
    print("=" * 60)
    print()
    print("  Server running at: http://localhost:8899")
    print()
    print("  Endpoints:")
    print("    /           - Home page with links & forms")
    print("    /search     - Reflected XSS (query param)")
    print("    /login      - SQL injection (POST form)")
    print("    /api/users  - Sensitive data exposure")
    print("    /profile    - XSS via user param")
    print("    /redirect   - Open redirect")
    print("    /file       - Path traversal")
    print("    /template   - Server-Side Template Injection")
    print("    /fetch      - SSRF")
    print("    /debug      - Debug info / secret exposure")
    print()
    print("  To scan: sentinal-fuzz scan http://localhost:8899")
    print("=" * 60)
    web.run_app(create_app(), host="127.0.0.1", port=8899)
