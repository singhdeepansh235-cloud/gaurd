"""Minimal phishing domain detection for Sentinel."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

from sentinal_fuzz.scoring import calculate_phishing_risk_score, phishing_status_from_score

TRUSTED_DOMAINS: tuple[str, ...] = (
    "google.com",
    "facebook.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "netflix.com",
    "instagram.com",
)

_DIGIT_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
})


@dataclass
class PhishingCheckResult:
    """Serializable phishing analysis result."""

    target: str
    domain: str
    status: str
    risk_score: int
    confidence_score: float
    detected_similar_domain: str | None = None
    reasons: list[str] = field(default_factory=list)
    domain_age_days: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "domain": self.domain,
            "status": self.status,
            "risk_score": self.risk_score,
            "confidence_score": round(self.confidence_score, 2),
            "detected_similar_domain": self.detected_similar_domain,
            "reasons": self.reasons,
            "domain_age_days": self.domain_age_days,
        }


def analyze_phishing_target(target: str) -> PhishingCheckResult:
    """Analyze a URL or domain for simple phishing indicators."""
    domain = extract_domain(target)
    registered = registered_domain(domain)
    reasons: list[str] = []
    weights: list[int] = []

    if domain in TRUSTED_DOMAINS or registered in TRUSTED_DOMAINS:
        return PhishingCheckResult(
            target=target,
            domain=domain,
            status="Safe",
            risk_score=0,
            confidence_score=0.99,
            reasons=["Domain matches a trusted whitelist entry."],
        )

    similar_domain, similarity = find_similar_domain(registered)
    if similar_domain is not None and similarity > 0.75:
        reasons.append(
            f"Domain is highly similar to trusted domain '{similar_domain}' "
            f"(similarity {similarity:.2f})."
        )
        weights.append(35)

    digit_match = detect_digit_substitution(registered)
    if digit_match:
        reasons.append(
            f"Domain uses number-for-letter substitution resembling '{digit_match}'."
        )
        weights.append(25)
        similar_domain = similar_domain or digit_match

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        reasons.append(f"Domain contains too many hyphens ({hyphen_count}).")
        weights.append(15)

    subdomain = extract_subdomain(domain)
    if len(subdomain) >= 25 or subdomain.count(".") >= 2:
        reasons.append("Domain uses an unusually long or deep subdomain.")
        weights.append(15)

    if is_ip_address(domain):
        reasons.append("URL uses an IP address instead of a domain name.")
        weights.append(40)

    risk_score = calculate_phishing_risk_score(weights)
    status = phishing_status_from_score(risk_score)

    if not reasons:
        reasons.append("No phishing indicators matched the current MVP rules.")

    return PhishingCheckResult(
        target=target,
        domain=domain,
        status=status,
        risk_score=risk_score,
        confidence_score=calculate_confidence(status, weights),
        detected_similar_domain=similar_domain,
        reasons=reasons,
    )


def extract_domain(target: str) -> str:
    """Extract and normalize the hostname from a URL or raw domain."""
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname or raw
    return host.strip().lower().rstrip(".")


def find_similar_domain(domain: str) -> tuple[str | None, float]:
    """Return the closest trusted domain and its similarity score."""
    best_match: str | None = None
    best_ratio = 0.0
    candidates = {domain, domain.split(".", 1)[0], *domain_similarity_tokens(domain)}

    for trusted_domain in TRUSTED_DOMAINS:
        trusted_label = trusted_domain.split(".", 1)[0]
        for candidate in candidates:
            ratio = SequenceMatcher(None, candidate, trusted_label).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = trusted_domain

    return best_match, best_ratio


def detect_digit_substitution(domain: str) -> str | None:
    """Detect simple number substitutions like g00gle -> google."""
    candidates = [candidate for candidate in domain_similarity_tokens(domain) if re.search(r"\d", candidate)]
    for candidate in candidates:
        normalized = candidate.translate(_DIGIT_SUBSTITUTIONS)
        for trusted_domain in TRUSTED_DOMAINS:
            trusted_label = trusted_domain.split(".", 1)[0]
            if normalized == trusted_label or trusted_label in normalized:
                return trusted_domain
    return None


def domain_similarity_tokens(domain: str) -> list[str]:
    """Build comparison tokens from labels and hyphen-delimited brand words."""
    base = domain.split(".", 1)[0]
    raw_tokens = [token for token in re.split(r"[-_.]+", base) if token]
    normalized = re.sub(r"[^a-z0-9]", "", base)
    translated = [token.translate(_DIGIT_SUBSTITUTIONS) for token in raw_tokens if re.search(r"\d", token)]
    if re.search(r"\d", normalized):
        translated.append(normalized.translate(_DIGIT_SUBSTITUTIONS))
    return list(dict.fromkeys(raw_tokens + [normalized] + translated))


def extract_subdomain(domain: str) -> str:
    """Return the subdomain portion of a domain when present."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def registered_domain(domain: str) -> str:
    """Reduce a hostname to its registrable-looking domain for MVP matching."""
    if is_ip_address(domain):
        return domain

    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def is_ip_address(domain: str) -> bool:
    """Check whether the hostname is an IPv4 or IPv6 address."""
    candidate = domain.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def calculate_confidence(status: str, weights: list[int]) -> float:
    """Estimate confidence based on the number and strength of signals."""
    if status == "Safe" and not weights:
        return 0.35
    if not weights:
        return 0.2

    confidence = 0.45 + (sum(weights) / 100.0) * 0.4 + len(weights) * 0.05
    return min(confidence, 0.99)
