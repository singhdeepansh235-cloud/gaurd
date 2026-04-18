"""Detectors package -- specialized vulnerability detection modules.

Each detector is a standalone class that can either:
- Run passively on every response (headers, exposure), or
- Generate targeted payloads and matchers (SSRF, SSTI, path traversal).
"""
