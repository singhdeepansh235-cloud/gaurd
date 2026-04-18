from __future__ import annotations

import pytest

from sentinal_fuzz.phishing_detection import analyze_phishing_target, extract_domain
from sentinal_fuzz.scoring import calculate_scan_risk_score


def test_extract_domain_from_url() -> None:
    assert extract_domain("https://login.g00gle.com/account/reset") == "login.g00gle.com"


def test_whitelisted_domain_is_safe() -> None:
    result = analyze_phishing_target("https://google.com/search")

    assert result.status == "Safe"
    assert result.risk_score == 0
    assert result.detected_similar_domain is None


def test_similar_domain_is_flagged_as_likely_phishing() -> None:
    result = analyze_phishing_target("https://secure-login-g00gle-account.com")

    assert result.status == "Likely Phishing"
    assert result.risk_score >= 60
    assert result.detected_similar_domain == "google.com"
    assert any("similar" in reason.lower() for reason in result.reasons)
    assert any("substitution" in reason.lower() for reason in result.reasons)


def test_ip_address_is_flagged() -> None:
    result = analyze_phishing_target("http://192.168.10.24/login")

    assert result.status in {"Suspicious", "Likely Phishing"}
    assert any("ip address" in reason.lower() for reason in result.reasons)


def test_scan_risk_score_helper_supports_dicts() -> None:
    score = calculate_scan_risk_score(
        [
            {"severity": "critical"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
    )
    assert score == 32


def test_phishing_check_endpoint() -> None:
    fastapi = pytest.importorskip("fastapi.testclient")
    pytest.importorskip("aiosqlite")

    from sentinal_fuzz.web.app import create_app

    TestClient = fastapi.TestClient
    client = TestClient(create_app())

    response = client.post("/api/phishing-check", json={"target": "http://g00gle-security-alert.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "Likely Phishing"
    assert payload["detected_similar_domain"] == "google.com"
    assert payload["confidence_score"] > 0.5
