"""Sentinal-Fuzz Web Interface.

Provides a browser-based UI for the Sentinal-Fuzz DAST scanner,
powered by FastAPI + HTMX with real-time WebSocket scan monitoring.

Usage::

    # Start the web server
    python -m sentinal_fuzz.web
    # or
    sentinal-fuzz web --port 8080
"""

__all__ = ["create_app"]
