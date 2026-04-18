"""Page routes — serves server-rendered HTML pages."""

from __future__ import annotations

import json
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from sentinal_fuzz.scoring import calculate_scan_risk_score
from sentinal_fuzz.web.services import db
from sentinal_fuzz.web.services.scan_manager import scan_manager

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard — landing page."""
    scans = await db.get_all_scans(limit=5)
    templates = request.app.state.templates
    total_scans = len(await db.get_all_scans(limit=1000))
    total_findings = sum(s.get("findings_count", 0) for s in await db.get_all_scans(limit=1000))
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "recent_scans": scans,
            "total_scans": total_scans,
            "total_findings": total_findings,
            "active_scans": [
                s.to_progress_dict() for s in scan_manager._active_scans.values()
                if s.status == "running"
            ],
        },
    )


@router.get("/scan/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """New scan form."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="scan_new.html",
    )


@router.get("/phishing-check", response_class=HTMLResponse)
async def phishing_check_page(request: Request):
    """Phishing detection page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="phishing_check.html",
    )


@router.get("/scan/{scan_id}/live", response_class=HTMLResponse)
async def live_scan_page(request: Request, scan_id: str):
    """Live scan monitoring page."""
    templates = request.app.state.templates
    state = scan_manager.get_scan_state(scan_id)

    # If scan is not active, check DB
    scan_data = None
    if state is None:
        scan_data = await db.get_scan(scan_id)
        if scan_data is None:
            return templates.TemplateResponse(
                request=request,
                name="error.html",
                context={
                    "error": "Scan not found",
                    "message": f"No scan with ID '{scan_id}' exists.",
                },
                status_code=404,
            )

    return templates.TemplateResponse(
        request=request,
        name="scan_live.html",
        context={
            "scan_id": scan_id,
            "state": state.to_progress_dict() if state else None,
            "scan_data": scan_data,
        },
    )


@router.get("/scan/{scan_id}/report", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    """Scan report page."""
    templates = request.app.state.templates

    # Check active scans first
    state = scan_manager.get_scan_state(scan_id)
    result_dict = None
    findings = []
    scan_info = None

    if state and state.result:
        result_dict = state.result.to_dict()
        findings = state.findings
        scan_info = {
            "id": scan_id,
            "target": state.target,
            "profile": state.profile,
            "status": state.status,
            "duration_seconds": round(state.elapsed_seconds(), 1),
            "endpoints_count": state.endpoints_total,
            "findings_count": state.findings_count,
            "risk_score": calculate_scan_risk_score(findings),
            "severity_counts": state.severity_counts,
        }
    else:
        # Fetch from DB
        scan_row = await db.get_scan(scan_id)
        if scan_row is None:
            return templates.TemplateResponse(
                request=request,
                name="error.html",
                context={
                    "error": "Scan not found",
                    "message": f"No scan with ID '{scan_id}' exists.",
                },
                status_code=404,
            )

        if scan_row.get("result_json"):
            result_dict = json.loads(scan_row["result_json"])
            findings = result_dict.get("findings", [])
        scan_info = {
            "id": scan_id,
            "target": scan_row["target"],
            "profile": scan_row["profile"],
            "status": scan_row["status"],
            "duration_seconds": scan_row.get("duration_seconds", 0),
            "endpoints_count": scan_row.get("endpoints_count", 0),
            "findings_count": scan_row.get("findings_count", 0),
            "risk_score": scan_row.get("risk_score", 0),
            "severity_counts": {},
        }
        # Compute severity counts
        for f in findings:
            sev = f.get("severity", "info")
            scan_info["severity_counts"][sev] = scan_info["severity_counts"].get(sev, 0) + 1

    return templates.TemplateResponse(
        request=request,
        name="scan_report.html",
        context={
            "scan_id": scan_id,
            "scan_info": scan_info,
            "result": result_dict,
            "findings": findings,
            "findings_json": json.dumps(findings, default=str),
        },
    )


@router.get("/scans", response_class=HTMLResponse)
async def scan_history_page(request: Request):
    """Scan history page."""
    templates = request.app.state.templates
    scans = await db.get_all_scans(limit=100)
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={
            "scans": scans,
        },
    )


@router.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request):
    """Template manager page."""
    tmpl = request.app.state.templates

    # Load templates from the templates directory
    from pathlib import Path
    template_dir = Path.cwd() / "templates"
    yaml_templates = []
    if template_dir.exists():
        import yaml
        for f in sorted(template_dir.glob("*.yaml")):
            try:
                with open(f, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                    if data:
                        data["_filename"] = f.name
                        yaml_templates.append(data)
            except Exception:
                pass

    return tmpl.TemplateResponse(
        request=request,
        name="templates_page.html",
        context={
            "templates": yaml_templates,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    templates = request.app.state.templates
    settings = await db.get_all_settings()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "settings": settings,
        },
    )
