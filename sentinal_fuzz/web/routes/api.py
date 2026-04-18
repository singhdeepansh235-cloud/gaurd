"""REST API routes for scan management, templates, and settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from sentinal_fuzz.web.services.gemini_analysis import analyze_with_gemini
from sentinal_fuzz.web.services.phishing_detection import detect_phishing
from sentinal_fuzz.web.services import db
from sentinal_fuzz.web.services.scan_manager import scan_manager

router = APIRouter()


# ── Request Models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_profile: str = "standard"
    depth: int | None = None
    concurrency: int | None = None
    timeout: int | None = None
    rate_limit: int | None = None
    auth_cookie: str | None = None
    auth_header: str | None = None
    proxy: str | None = None
    exclude_patterns: list[str] | None = None
    templates: list[str] | None = None
    js_rendering: bool = False


class SettingsUpdate(BaseModel):
    settings: dict[str, str]


class PhishingCheckRequest(BaseModel):
    target: str


async def analyze_url(url: str) -> dict[str, object]:
    """Run comprehensive URL analysis and merge phishing signals into the response."""
    phishing = detect_phishing(url)
    ai_analysis = await analyze_with_gemini(url, phishing)

    # Base risk from heuristic confidence
    risk_score = phishing.get("confidence", 0)
    if phishing["status"] == "Safe":
        risk_score = 0
    elif phishing["status"] == "Suspicious":
        risk_score = max(risk_score, 25)
    elif phishing["status"] == "Likely Phishing":
        risk_score = max(risk_score, 55)

    # Boost from AI analysis
    if ai_analysis.get("enabled"):
        if ai_analysis["verdict"] == "Suspicious":
            risk_score = max(risk_score, risk_score + 10)
        elif ai_analysis["verdict"] == "Likely Phishing":
            risk_score = max(risk_score, risk_score + 20)

    return {
        "risk_score": min(risk_score, 100),
        "phishing": phishing,
        "analysis_engine": ai_analysis,
    }


# ── Scan Endpoints ─────────────────────────────────────────────────

@router.post("/scans")
async def create_scan(req: ScanRequest):
    """Start a new scan."""
    # Build config dict (remove None values)
    config = {k: v for k, v in req.model_dump().items() if v is not None}

    try:
        state = await scan_manager.start_scan(config)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "scan_id": state.scan_id,
        "target": state.target,
        "profile": state.profile,
        "status": state.status,
    }


@router.get("/scans")
async def list_scans():
    """List all scans."""
    scans = await db.get_all_scans(limit=100)
    # Also inject active scan states
    for scan in scans:
        state = scan_manager.get_scan_state(scan["id"])
        if state:
            scan["status"] = state.status
            scan["stage"] = state.stage
    return scans


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details."""
    # Check active first
    state = scan_manager.get_scan_state(scan_id)
    if state:
        return state.to_progress_dict()

    # Check DB
    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Don't send full result_json in listing
    if scan.get("result_json"):
        result = json.loads(scan["result_json"])
        scan["findings_preview"] = result.get("findings", [])[:5]
    scan.pop("result_json", None)
    scan.pop("config_json", None)
    return scan


@router.get("/scans/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get full scan result."""
    state = scan_manager.get_scan_state(scan_id)
    if state and state.result:
        return state.result.to_dict()

    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("result_json"):
        raise HTTPException(status_code=404, detail="Scan result not available yet")
    return json.loads(scan["result_json"])


@router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Stop a running scan."""
    stopped = await scan_manager.stop_scan(scan_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="No active scan with that ID")
    return {"status": "cancelled", "scan_id": scan_id}


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan record."""
    deleted = await db.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "scan_id": scan_id}


# ── Template Endpoints ─────────────────────────────────────────────

@router.get("/templates")
async def list_templates():
    """List all fuzzing templates."""
    template_dir = Path.cwd() / "templates"
    if not template_dir.exists():
        return []

    import yaml
    templates = []
    for f in sorted(template_dir.glob("*.yaml")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                if data:
                    data["_filename"] = f.name
                    templates.append(data)
        except Exception:
            pass
    return templates


@router.post("/templates/validate")
async def validate_template(body: dict[str, Any]):
    """Validate a template YAML structure."""
    errors = []
    if "id" not in body:
        errors.append("Missing required field: id")
    if "info" not in body and "name" not in body:
        errors.append("Missing required field: info or name")
    if "payloads" not in body and "matchers" not in body:
        errors.append("Template needs payloads or matchers")
    return {"valid": len(errors) == 0, "errors": errors}


# ── Settings Endpoints ─────────────────────────────────────────────

@router.get("/settings")
async def get_settings():
    """Get all settings."""
    return await db.get_all_settings()


@router.post("/settings")
async def update_settings(update: SettingsUpdate):
    """Update settings."""
    for key, value in update.settings.items():
        await db.set_setting(key, value)
    return {"status": "updated"}


@router.post("/phishing-check")
async def phishing_check(req: PhishingCheckRequest):
    """Analyze a URL or domain for phishing indicators."""
    return JSONResponse(await analyze_url(req.target))
