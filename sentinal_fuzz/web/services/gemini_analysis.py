"""Optional Gemini-backed analysis engine for phishing review."""

from __future__ import annotations

import json
import os
import asyncio

import httpx

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


async def analyze_with_gemini(url: str, phishing: dict[str, object], live: dict[str, object]) -> dict[str, object]:
    """Call Gemini to summarize phishing risk and reasoning using heuristics and live network data.

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
        "You are an elite cybersecurity AI specializing in real-time phishing detection. "
        "Review the target URL, the local heuristic signals, and the live network analysis (DNS, SSL, WHOIS, Domain age, HTTP features, and page content). "
        "Your task: evaluate this evidence comprehensively and return a compact JSON object. "
        "The JSON must have the following keys: \"verdict\", \"summary\", \"signals\". "
        "Allowed \"verdict\" values: Safe, Suspicious, Likely Phishing. "
        "Keep \"summary\" under 60 words, prioritizing the most critical findings (like mismatched brands, fake secure keywords, or missing SSL). "
        "Keep \"signals\" as an array of short, impactful strings detailing the most critical evidence. "
        "Do not output markdown, just raw JSON.\n\n"
        f"URL: {url}\n"
        f"Heuristic result: {json.dumps(phishing, default=str)}\n"
        f"Live network & DOM context: {json.dumps(live, default=str)}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }

    max_retries = 3
    base_delay = 2.0

    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    GEMINI_API_URL.format(model=model),
                    headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                    json=payload,
                )
                
                # Check for rate limit explicitly
                if response.status_code == 429 and attempt < max_retries - 1:
                    await asyncio.sleep(base_delay * (2 ** attempt))
                    continue
                    
                response.raise_for_status()
                break  # Successful request, break out of retry loop

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429 and attempt < max_retries - 1:
                await asyncio.sleep(base_delay * (2 ** attempt))
                continue
            return {
                "enabled": False,
                "provider": "gemini",
                "model": model,
                "verdict": phishing.get("status", "Unknown"),
                "summary": f"Gemini request failed; using heuristic result instead. Error: {exc}",
                "signals": phishing.get("reasons", []),
            }
        except Exception as exc:
            return {
                "enabled": False,
                "provider": "gemini",
                "model": model,
                "verdict": phishing.get("status", "Unknown"),
                "summary": f"Gemini request failed; using heuristic result instead. Error: {exc}",
                "signals": phishing.get("reasons", []),
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
