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
"""

from __future__ import annotations

import re
import math
from difflib import SequenceMatcher
from urllib.parse import urlparse, unquote


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
