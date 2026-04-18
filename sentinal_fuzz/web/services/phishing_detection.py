"""Comprehensive phishing detection service for URL analysis.

Performs multi-layer heuristic analysis:
  1. Domain similarity to known brands (with exact-match whitelisting)
  2. Homoglyph / leetspeak substitution detection
  3. Suspicious TLD analysis
  4. IP-based URL detection
  5. Suspicious keyword detection (login, secure, verify, etc.)
  6. URL structure anomalies (length, subdomain depth, encoded chars)
  7. Punycode / IDN homograph detection
  8. URL shortener detection

Live checks (network-based):
  9.  DNS resolution verification
  10. SSL certificate validation & analysis
  11. HTTP response & redirect chain analysis
  12. Page content scanning (credential harvesting detection)
  13. Security headers audit
  14. Domain age estimation (WHOIS)
"""

from __future__ import annotations

import re
import ssl
import math
import socket
import asyncio
import logging
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, unquote

import httpx

logger = logging.getLogger(__name__)


# ── Trusted brand domains (exact hostnames that should NEVER be flagged) ──

TRUSTED_DOMAINS: dict[str, list[str]] = {
    # brand_label -> list of known legitimate hostnames
    "google":    ["google.com", "www.google.com", "accounts.google.com",
                  "mail.google.com", "drive.google.com", "maps.google.com"],
    "facebook":  ["facebook.com", "www.facebook.com", "m.facebook.com",
                  "web.facebook.com"],
    "amazon":    ["amazon.com", "www.amazon.com", "amazon.in", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
                  "outlook.com", "live.com"],
    "apple":     ["apple.com", "www.apple.com", "icloud.com", "appleid.apple.com"],
    "paypal":    ["paypal.com", "www.paypal.com"],
    "netflix":   ["netflix.com", "www.netflix.com"],
    "instagram": ["instagram.com", "www.instagram.com"],
    "twitter":   ["twitter.com", "x.com", "www.twitter.com"],
    "linkedin":  ["linkedin.com", "www.linkedin.com"],
    "github":    ["github.com", "www.github.com"],
    "dropbox":   ["dropbox.com", "www.dropbox.com"],
    "chase":     ["chase.com", "www.chase.com"],
    "wellsfargo": ["wellsfargo.com", "www.wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "www.bankofamerica.com"],
    "yahoo":     ["yahoo.com", "www.yahoo.com", "mail.yahoo.com"],
    "spotify":   ["spotify.com", "www.spotify.com", "open.spotify.com"],
    "steam":     ["steampowered.com", "store.steampowered.com",
                  "steamcommunity.com"],
    "whatsapp":  ["whatsapp.com", "web.whatsapp.com", "www.whatsapp.com"],
    "telegram":  ["telegram.org", "web.telegram.org", "t.me"],
    "discord":   ["discord.com", "discord.gg"],
    "twitch":    ["twitch.tv", "www.twitch.tv"],
    "reddit":    ["reddit.com", "www.reddit.com", "old.reddit.com"],
    "ebay":      ["ebay.com", "www.ebay.com"],
    "walmart":   ["walmart.com", "www.walmart.com"],
    "stripe":    ["stripe.com", "dashboard.stripe.com"],
}

# Flat set for fast exact-match whitelisting
_LEGITIMATE_HOSTNAMES: set[str] = set()
for _hosts in TRUSTED_DOMAINS.values():
    _LEGITIMATE_HOSTNAMES.update(_hosts)

# Brand labels for similarity matching
BRAND_LABELS: list[str] = list(TRUSTED_DOMAINS.keys())


# ── Suspicious TLDs commonly used in phishing ──

SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",          # Freenom free TLDs
    ".xyz", ".top", ".club", ".work", ".buzz",   # Cheap TLDs
    ".info", ".icu", ".cam", ".rest", ".surf",
    ".click", ".link", ".loan", ".download",
    ".win", ".bid", ".date", ".racing", ".review",
    ".trade", ".stream", ".party", ".science",
    ".zip", ".mov",                              # Confusing TLDs
}

# ── Suspicious keywords commonly found in phishing URLs ──

PHISHING_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "logon", "log-on",
    "verify", "verification", "confirm", "update",
    "secure", "security", "account", "alert",
    "suspend", "restricted", "unusual", "unlock",
    "recover", "restore", "validate", "authenticate",
    "billing", "payment", "invoice", "refund",
    "support", "helpdesk", "service",
    "webmail", "webscr", "cgi-bin",
]

# ── Known URL shortener domains ──

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "bl.ink",
    "short.io", "tiny.cc", "lnkd.in", "db.tt",
}

# ── Homoglyph / leetspeak substitution map ──

HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i",
    # Cyrillic/Greek lookalikes (common in IDN homograph attacks)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x",
}

# ── Security headers we expect on legitimate sites ──

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "XSS Protection",
    "referrer-policy": "Referrer Policy",
    "permissions-policy": "Permissions Policy",
}

# ── Suspicious page content patterns ──

CREDENTIAL_HARVEST_PATTERNS: list[tuple[str, str]] = [
    (r'<input[^>]*type=["\']password["\']', "Password input field detected"),
    (r'<form[^>]*action=["\'](?!https?://(?:www\.)?(?:' + "|".join(
        re.escape(d) for d in list(_LEGITIMATE_HOSTNAMES)[:20]
    ) + r'))', "Form submits to external/unknown domain"),
    (r'<input[^>]*(?:name|id)=["\'](?:ssn|social|cardnumber|cvv|ccnum|credit)', "Sensitive data field (SSN/CC) detected"),
    (r'<input[^>]*(?:name|id)=["\'](?:user|email|login|usr|uname)', "Username/email input field detected"),
    (r'(?:document\.cookie|localStorage|sessionStorage)', "JavaScript accessing browser storage"),
    (r'(?:atob|btoa|eval|Function\()', "Obfuscated JavaScript detected"),
    (r'<meta[^>]*http-equiv=["\']refresh["\']', "Auto-redirect via meta refresh"),
    (r'(?:keylog|keystroke|onkeypress|onkeydown)[^>]*=', "Potential keystroke logging"),
]


# ── Core functions ──────────────────────────────────────────────────


def extract_domain(url: str) -> str:
    """Extract a normalized hostname from a URL or raw domain."""
    candidate = url.strip()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    return (parsed.hostname or candidate).lower().strip(".")


def extract_full_url_parts(url: str) -> dict[str, str]:
    """Extract scheme, hostname, path, and query from a URL."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    return {
        "scheme": parsed.scheme or "",
        "hostname": (parsed.hostname or "").lower().strip("."),
        "path": unquote(parsed.path or ""),
        "query": unquote(parsed.query or ""),
        "full": candidate,
    }


def similarity(a: str, b: str) -> float:
    """Return string similarity ratio using SequenceMatcher."""
    return SequenceMatcher(None, a, b).ratio()


def normalize_homoglyphs(text: str) -> str:
    """Replace common homoglyphs/leetspeak with their ASCII equivalents."""
    result = []
    for ch in text:
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(result)


def _get_tld(domain: str) -> str:
    """Extract the TLD (last dot-separated segment with dot prefix)."""
    parts = domain.rsplit(".", 1)
    return f".{parts[-1]}" if len(parts) > 1 else ""


def _is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address (v4 or v6-ish)."""
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return True
    # IPv6 bracket notation or raw
    if hostname.startswith("[") or ":" in hostname:
        return True
    return False


# ── Live network checks ────────────────────────────────────────────


async def check_dns_resolution(domain: str) -> dict:
    """Verify the domain resolves in DNS."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
        )
        ips = list(set(r[4][0] for r in result))
        return {
            "resolves": True,
            "ip_addresses": ips[:5],
            "record_count": len(ips),
        }
    except socket.gaierror:
        return {
            "resolves": False,
            "ip_addresses": [],
            "record_count": 0,
            "error": "Domain does not resolve — DNS lookup failed",
        }
    except Exception as e:
        return {
            "resolves": None,
            "ip_addresses": [],
            "error": str(e),
        }


async def check_ssl_certificate(domain: str) -> dict:
    """Validate and analyze the SSL certificate."""
    try:
        loop = asyncio.get_event_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(8)
                s.connect((domain, 443))
                cert = s.getpeercert()
                return cert

        cert = await loop.run_in_executor(None, _get_cert)

        # Parse certificate details
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        san = [entry[1] for entry in cert.get("subjectAltName", ())]

        # Parse expiry
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (expiry - datetime.now()).days
        except Exception:
            days_until_expiry = None

        # Parse issue date
        try:
            issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            cert_age_days = (datetime.now() - issued).days
        except Exception:
            cert_age_days = None

        # Check for free/automated CAs (often used by phishing)
        issuer_org = issuer.get("organizationName", "").lower()
        is_free_cert = any(
            ca in issuer_org
            for ca in ["let's encrypt", "letsencrypt", "zerossl", "buypass", "ssl.com free"]
        )

        return {
            "valid": True,
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", "Unknown"),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "cert_age_days": cert_age_days,
            "san_count": len(san),
            "san_domains": san[:8],
            "is_free_cert": is_free_cert,
            "is_wildcard": any("*" in s for s in san),
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "valid": False,
            "error": f"SSL certificate verification failed: {e.verify_message}",
            "self_signed": "self-signed" in str(e).lower() or "self signed" in str(e).lower(),
        }
    except (ConnectionRefusedError, socket.timeout, OSError):
        return {
            "valid": None,
            "error": "Could not connect to port 443 — SSL not available",
        }
    except Exception as e:
        return {
            "valid": None,
            "error": f"SSL check error: {str(e)}",
        }


async def check_http_response(url: str) -> dict:
    """Analyze HTTP response, redirects, and headers."""
    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            max_redirects=10,
            verify=False,  # We check SSL separately
        ) as client:
            response = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            })

            # Track redirect chain
            redirect_chain = []
            for r in response.history:
                redirect_chain.append({
                    "url": str(r.url),
                    "status": r.status_code,
                })

            # Final destination
            final_url = str(response.url)
            final_domain = urlparse(final_url).hostname or ""

            # Analyze response headers
            headers = dict(response.headers)
            content_type = headers.get("content-type", "")

            # Check security headers
            security_headers_present = {}
            security_headers_missing = []
            for header_key, header_name in SECURITY_HEADERS.items():
                if header_key in headers:
                    security_headers_present[header_name] = headers[header_key][:120]
                else:
                    security_headers_missing.append(header_name)

            # Page content analysis
            content = response.text[:50000] if response.status_code == 200 else ""
            content_signals = []

            if content:
                for pattern, description in CREDENTIAL_HARVEST_PATTERNS:
                    try:
                        if re.search(pattern, content, re.IGNORECASE):
                            content_signals.append(description)
                    except re.error:
                        pass

                # Check for suspicious page title
                title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                page_title = title_match.group(1).strip() if title_match else ""

                # Check for iframe abuse
                iframe_count = len(re.findall(r"<iframe", content, re.IGNORECASE))
                if iframe_count > 2:
                    content_signals.append(f"Multiple iframes detected ({iframe_count}) — possible clickjacking")

                # Check for data exfiltration patterns
                if re.search(r"(?:fetch|XMLHttpRequest|ajax)\s*\([^)]*(?:\.xyz|\.tk|\.ml|\.top)", content, re.IGNORECASE):
                    content_signals.append("JavaScript sends data to suspicious domain")

                # Hidden form fields
                hidden_fields = len(re.findall(r'<input[^>]*type=["\']hidden["\']', content, re.IGNORECASE))
                if hidden_fields > 5:
                    content_signals.append(f"Excessive hidden form fields ({hidden_fields})")

                # Brand impersonation in page content
                brand_mentions = []
                for brand in BRAND_LABELS:
                    if brand.lower() in content.lower() and brand.lower() not in final_domain.lower():
                        brand_mentions.append(brand)
                if brand_mentions:
                    content_signals.append(f"Page content mentions brands not matching domain: {', '.join(brand_mentions[:3])}")

            else:
                page_title = ""

            return {
                "reachable": True,
                "status_code": response.status_code,
                "final_url": final_url,
                "final_domain": final_domain,
                "redirect_count": len(redirect_chain),
                "redirect_chain": redirect_chain,
                "content_type": content_type,
                "page_title": page_title[:200],
                "server": headers.get("server", "Unknown")[:80],
                "security_headers_present": security_headers_present,
                "security_headers_missing": security_headers_missing,
                "content_signals": content_signals,
                "content_length": len(content),
                "has_login_form": any("password" in s.lower() or "username" in s.lower() for s in content_signals),
            }
    except httpx.TooManyRedirects:
        return {
            "reachable": False,
            "error": "Too many redirects (>10) — likely redirect loop",
            "redirect_count": 10,
            "content_signals": ["Excessive redirect chain — possible evasion technique"],
        }
    except httpx.ConnectTimeout:
        return {
            "reachable": False,
            "error": "Connection timed out",
            "content_signals": [],
        }
    except Exception as e:
        return {
            "reachable": False,
            "error": f"HTTP request failed: {str(e)[:200]}",
            "content_signals": [],
        }


async def check_domain_age(domain: str) -> dict:
    """Estimate domain age via WHOIS (best-effort, no external lib required)."""
    try:
        loop = asyncio.get_event_loop()

        def _whois_query():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            # Determine the WHOIS server
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            whois_servers = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "io": "whois.nic.io",
                "xyz": "whois.nic.xyz",
                "info": "whois.afilias.net",
                "co": "whois.nic.co",
            }
            server = whois_servers.get(tld, f"whois.nic.{tld}")

            try:
                s.connect((server, 43))
                s.send(f"{domain}\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                return data.decode("utf-8", errors="ignore")
            finally:
                s.close()

        whois_text = await loop.run_in_executor(None, _whois_query)

        # Parse creation date from WHOIS
        creation_patterns = [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"created:\s*(.+)",
            r"Registration Date:\s*(.+)",
            r"Registered:\s*(.+)",
            r"Domain Registration Date:\s*(.+)",
        ]

        creation_date = None
        for pattern in creation_patterns:
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                date_str = match.group(1).strip()
                # Try common date formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%d-%b-%Y",
                    "%d/%m/%Y",
                ]:
                    try:
                        creation_date = datetime.strptime(date_str[:19], fmt[:len(date_str)])
                        break
                    except ValueError:
                        continue
                if creation_date:
                    break

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {
                "available": True,
                "creation_date": creation_date.strftime("%Y-%m-%d"),
                "age_days": age_days,
                "is_new": age_days < 90,
                "is_very_new": age_days < 30,
            }
        else:
            # Check if domain is available / not registered
            if "No match" in whois_text or "NOT FOUND" in whois_text.upper() or "No Data Found" in whois_text:
                return {
                    "available": True,
                    "creation_date": None,
                    "age_days": None,
                    "not_registered": True,
                    "note": "Domain appears to not be registered",
                }
            return {
                "available": True,
                "creation_date": None,
                "age_days": None,
                "note": "WHOIS data found but creation date not parseable",
            }
    except Exception as e:
        return {
            "available": False,
            "error": f"WHOIS lookup failed: {str(e)[:150]}",
        }


# ── Main detection function ─────────────────────────────────────────


def detect_phishing(url: str) -> dict[str, object]:
    """Perform comprehensive phishing heuristic analysis on a URL/domain.

    Returns a dict with:
      - status: 'Safe' | 'Suspicious' | 'Likely Phishing'
      - confidence: 0-100
      - matched_brand: str | None
      - matched_domain: str | None  (closest legitimate domain)
      - reasons: list[str]
      - checks: dict of individual check results
    """
    parts = extract_full_url_parts(url)
    domain = parts["hostname"]
    path = parts["path"]
    scheme = parts["scheme"]
    full_url = parts["full"]

    reasons: list[str] = []
    checks: dict[str, dict] = {}
    score: float = 0.0  # cumulative risk score (0-100)
    matched_brand: str | None = None
    matched_domain: str | None = None

    # ────────────────────────────────────────────────────────────
    # 0. Exact whitelist check — known legitimate domains are SAFE
    # ────────────────────────────────────────────────────────────
    if domain in _LEGITIMATE_HOSTNAMES:
        checks["whitelist"] = {"passed": True, "note": "Domain is a known legitimate hostname."}
        return {
            "status": "Safe",
            "confidence": 5,
            "matched_brand": None,
            "matched_domain": None,
            "reasons": [],
            "checks": checks,
        }

    # ────────────────────────────────────────────────────────────
    # 1. IP-based URL detection
    # ────────────────────────────────────────────────────────────
    if _is_ip_address(domain):
        reasons.append("URL uses a raw IP address instead of a domain name — a strong phishing indicator.")
        score += 30
        checks["ip_based"] = {"flagged": True, "ip": domain}
    else:
        checks["ip_based"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # 2. Brand similarity / lookalike detection
    # ────────────────────────────────────────────────────────────
    label = domain.split(".")[0]  # first subdomain segment
    normalized_label = normalize_homoglyphs(label)
    # Also split on hyphens/underscores to get tokens
    tokens = [t for t in re.split(r"[-_.]+", label) if t]
    normalized_tokens = [normalize_homoglyphs(t) for t in tokens]

    best_sim = 0.0
    best_brand = None
    for brand in BRAND_LABELS:
        # Compare raw label, normalized label, and individual tokens
        scores = [
            similarity(label, brand),
            similarity(normalized_label, brand),
        ] + [
            similarity(nt, brand) for nt in normalized_tokens
        ]
        top = max(scores)
        if top > best_sim:
            best_sim = top
            best_brand = brand

    if best_brand and best_sim > 0.70:
        matched_brand = best_brand
        # Find the primary legitimate domain for that brand
        matched_domain = TRUSTED_DOMAINS[best_brand][0]

        if best_sim > 0.90:
            reason = f"Domain '{domain}' is nearly identical to trusted brand '{best_brand}' (similarity {best_sim:.0%})."
            score += 35
        else:
            reason = f"Domain '{domain}' is visually similar to trusted brand '{best_brand}' (similarity {best_sim:.0%})."
            score += 20
        reasons.append(reason)
        checks["brand_similarity"] = {
            "flagged": True,
            "brand": best_brand,
            "similarity": round(best_sim, 3),
            "legitimate_domain": matched_domain,
        }
    else:
        checks["brand_similarity"] = {"flagged": False, "best_score": round(best_sim, 3)}

    # ────────────────────────────────────────────────────────────
    # 3. Homoglyph / leetspeak detection
    # ────────────────────────────────────────────────────────────
    has_homoglyphs = any(ch in HOMOGLYPH_MAP for ch in label)
    if has_homoglyphs and not _is_ip_address(domain):
        substitutions = [ch for ch in label if ch in HOMOGLYPH_MAP]
        reasons.append(
            f"Domain contains character substitutions ({', '.join(repr(c) for c in substitutions[:5])}) "
            "commonly used in homoglyph phishing attacks."
        )
        score += 15
        checks["homoglyphs"] = {"flagged": True, "substitutions": substitutions[:5]}
    else:
        checks["homoglyphs"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # 4. Suspicious TLD check
    # ────────────────────────────────────────────────────────────
    tld = _get_tld(domain)
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Domain uses suspicious TLD '{tld}' which is frequently associated with phishing.")
        score += 15
        checks["suspicious_tld"] = {"flagged": True, "tld": tld}
    else:
        checks["suspicious_tld"] = {"flagged": False, "tld": tld}

    # ────────────────────────────────────────────────────────────
    # 5. Suspicious keyword detection
    # ────────────────────────────────────────────────────────────
    full_text = f"{domain}/{path}".lower()
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_text]
    if found_keywords:
        reasons.append(
            f"URL contains suspicious keywords: {', '.join(found_keywords[:6])}."
        )
        score += min(5 * len(found_keywords), 20)
        checks["suspicious_keywords"] = {"flagged": True, "keywords": found_keywords[:6]}
    else:
        checks["suspicious_keywords"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # 6. Subdomain depth check
    # ────────────────────────────────────────────────────────────
    subdomain_parts = [p for p in domain.split(".") if p]
    if len(subdomain_parts) > 3:
        reasons.append(
            f"Domain has an unusually deep subdomain chain ({len(subdomain_parts)} levels), "
            "which can be used to disguise the real destination."
        )
        score += 10
        checks["subdomain_depth"] = {"flagged": True, "depth": len(subdomain_parts)}
    else:
        checks["subdomain_depth"] = {"flagged": False, "depth": len(subdomain_parts)}

    # ────────────────────────────────────────────────────────────
    # 7. Hyphen abuse detection
    # ────────────────────────────────────────────────────────────
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        reasons.append(
            f"Domain contains {hyphen_count} hyphens — excessive hyphens are common in phishing domains."
        )
        score += 10
        checks["hyphen_abuse"] = {"flagged": True, "count": hyphen_count}
    elif hyphen_count == 1 and matched_brand:
        reasons.append("Domain contains a hyphen combined with brand impersonation.")
        score += 5
        checks["hyphen_abuse"] = {"flagged": True, "count": hyphen_count}
    elif hyphen_count >= 1 and tld in SUSPICIOUS_TLDS:
        reasons.append("Domain contains hyphens combined with a suspicious TLD.")
        score += 8
        checks["hyphen_abuse"] = {"flagged": True, "count": hyphen_count}
    else:
        checks["hyphen_abuse"] = {"flagged": False, "count": hyphen_count}

    # ────────────────────────────────────────────────────────────
    # 8. URL length anomaly
    # ────────────────────────────────────────────────────────────
    if len(full_url) > 100:
        reasons.append(
            f"URL is unusually long ({len(full_url)} characters) — "
            "long URLs can hide malicious destinations."
        )
        score += 5
        checks["url_length"] = {"flagged": True, "length": len(full_url)}
    else:
        checks["url_length"] = {"flagged": False, "length": len(full_url)}

    # ────────────────────────────────────────────────────────────
    # 9. HTTPS check
    # ────────────────────────────────────────────────────────────
    if scheme == "http":
        reasons.append("URL uses HTTP instead of HTTPS — no transport encryption.")
        score += 5
        checks["https"] = {"flagged": True, "scheme": scheme}
    else:
        checks["https"] = {"flagged": False, "scheme": scheme}

    # ────────────────────────────────────────────────────────────
    # 10. Encoded characters in domain
    # ────────────────────────────────────────────────────────────
    if "%" in url.split("/")[2] if len(url.split("/")) > 2 else False:
        reasons.append("Domain contains URL-encoded characters, possibly hiding the real destination.")
        score += 10
        checks["encoded_chars"] = {"flagged": True}
    else:
        checks["encoded_chars"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # 11. URL shortener detection
    # ────────────────────────────────────────────────────────────
    if domain in URL_SHORTENERS:
        reasons.append(
            f"URL uses a known URL shortener ({domain}) — the real destination is hidden."
        )
        score += 25
        checks["url_shortener"] = {"flagged": True, "service": domain}
    else:
        checks["url_shortener"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # 12. Punycode / IDN detection
    # ────────────────────────────────────────────────────────────
    if domain.startswith("xn--") or any(
        p.startswith("xn--") for p in domain.split(".")
    ):
        reasons.append(
            "Domain uses Punycode (internationalized domain name) — "
            "this technique is used in IDN homograph attacks."
        )
        score += 20
        checks["punycode"] = {"flagged": True}
    else:
        checks["punycode"] = {"flagged": False}

    # ────────────────────────────────────────────────────────────
    # Final verdict
    # ────────────────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 45:
        status = "Likely Phishing"
    elif score >= 20:
        status = "Suspicious"
    else:
        status = "Safe"

    # Confidence: maps risk score to a 0-100 confidence in the verdict
    if status == "Safe":
        confidence = max(5, 100 - int(score * 3))
    else:
        confidence = min(100, int(score * 1.2) + 15)

    return {
        "status": status,
        "confidence": confidence,
        "matched_brand": matched_brand,
        "matched_domain": matched_domain,
        "reasons": reasons,
        "checks": checks,
    }


async def run_live_checks(url: str, domain: str) -> dict:
    """Run all live network-based checks in parallel."""
    parts = extract_full_url_parts(url)
    full_url = parts["full"]

    # Run DNS, SSL, HTTP, and WHOIS in parallel
    dns_task = check_dns_resolution(domain)
    ssl_task = check_ssl_certificate(domain)
    http_task = check_http_response(full_url)
    whois_task = check_domain_age(domain)

    dns_result, ssl_result, http_result, whois_result = await asyncio.gather(
        dns_task, ssl_task, http_task, whois_task,
        return_exceptions=True,
    )

    # Handle exceptions gracefully
    if isinstance(dns_result, Exception):
        dns_result = {"resolves": None, "error": str(dns_result)}
    if isinstance(ssl_result, Exception):
        ssl_result = {"valid": None, "error": str(ssl_result)}
    if isinstance(http_result, Exception):
        http_result = {"reachable": False, "error": str(http_result), "content_signals": []}
    if isinstance(whois_result, Exception):
        whois_result = {"available": False, "error": str(whois_result)}

    # ── Score adjustments from live checks ──
    live_reasons: list[str] = []
    live_score: float = 0.0

    # DNS
    if dns_result.get("resolves") is False:
        live_reasons.append("Domain does not resolve in DNS — this domain may not exist or is parked.")
        live_score += 15

    # SSL
    if ssl_result.get("valid") is False:
        if ssl_result.get("self_signed"):
            live_reasons.append("SSL certificate is self-signed — legitimate sites use trusted CAs.")
            live_score += 20
        else:
            live_reasons.append(f"SSL certificate invalid: {ssl_result.get('error', 'unknown error')}")
            live_score += 15
    elif ssl_result.get("valid") is True:
        if ssl_result.get("cert_age_days") is not None and ssl_result["cert_age_days"] < 14:
            live_reasons.append(f"SSL certificate was issued only {ssl_result['cert_age_days']} days ago — very new certificate.")
            live_score += 8
        if ssl_result.get("is_free_cert"):
            live_reasons.append("Uses a free automated SSL certificate (common with phishing sites).")
            live_score += 5

    # HTTP
    if http_result.get("reachable"):
        if http_result.get("redirect_count", 0) > 3:
            live_reasons.append(f"Excessive redirect chain ({http_result['redirect_count']} redirects) — possible evasion.")
            live_score += 10

        # Security headers
        missing = http_result.get("security_headers_missing", [])
        if len(missing) >= 5:
            live_reasons.append(f"Missing {len(missing)} critical security headers — poor security configuration.")
            live_score += 8

        # Content signals
        content_signals = http_result.get("content_signals", [])
        if content_signals:
            for signal in content_signals[:4]:
                live_reasons.append(f"Content analysis: {signal}")
            live_score += min(10 * len(content_signals), 30)

        if http_result.get("has_login_form"):
            live_reasons.append("Page contains a login/credential form — high risk if combined with brand impersonation.")
            live_score += 15
    else:
        err = http_result.get("error", "")
        if "Too many redirects" in err:
            live_reasons.append("Too many redirects detected — likely redirect loop or evasion technique.")
            live_score += 10

    # WHOIS / Domain age
    if whois_result.get("available"):
        if whois_result.get("not_registered"):
            live_reasons.append("Domain appears to not be registered — URL may be fraudulent.")
            live_score += 20
        elif whois_result.get("is_very_new"):
            live_reasons.append(f"Domain was registered only {whois_result['age_days']} days ago — newly registered domains are high-risk.")
            live_score += 15
        elif whois_result.get("is_new"):
            live_reasons.append(f"Domain was registered {whois_result['age_days']} days ago — relatively new domain.")
            live_score += 8

    return {
        "dns": dns_result,
        "ssl": ssl_result,
        "http": http_result,
        "whois": whois_result,
        "live_reasons": live_reasons,
        "live_score": min(live_score, 50),  # Cap live score contribution
    }
