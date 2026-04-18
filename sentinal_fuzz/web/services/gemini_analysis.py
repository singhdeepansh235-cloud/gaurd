"""Optional Gemini-backed analysis engine for phishing review."""

from __future__ import annotations

import json
import os

import httpx

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


async def analyze_with_gemini(url: str, phishing: dict[str, object]) -> dict[str, object]:
    """Call Gemini to summarize phishing risk and reasoning.

    Falls back cleanly when no API key is configured.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    if not api_key:
        return {
            "enabled": False,
            "provider": "gemini",
            "model": model,
            "verdict": phishing["status"],
            "summary": "Gemini analysis is disabled. Set GEMINI_API_KEY to enable AI-assisted review.",
            "signals": phishing["reasons"],
        }

    prompt = (
        "You are a phishing detection assistant. Review the URL and heuristic signals "
        "and return compact JSON with keys verdict, summary, signals. "
        "Allowed verdict values: Safe, Suspicious, Likely Phishing. "
        "Keep summary under 50 words and signals as a short array of strings.\n\n"
        f"URL: {url}\n"
        f"Heuristic result: {json.dumps(phishing)}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                GEMINI_API_URL.format(model=model),
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
    except Exception as exc:
        return {
            "enabled": False,
            "provider": "gemini",
            "model": model,
            "verdict": phishing["status"],
            "summary": f"Gemini request failed; using heuristic result instead. Error: {exc}",
            "signals": phishing["reasons"],
        }

    data = response.json()
    text = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "{}")
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {"verdict": phishing["status"], "summary": text, "signals": phishing["reasons"]}

    return {
        "enabled": True,
        "provider": "gemini",
        "model": model,
        "verdict": parsed.get("verdict", phishing["status"]),
        "summary": parsed.get("summary", "No Gemini summary returned."),
        "signals": parsed.get("signals", phishing["reasons"]),
    }
