"""WebSocket route for real-time scan monitoring."""

from __future__ import annotations

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from sentinal_fuzz.web.services.scan_manager import scan_manager
from sentinal_fuzz.web.services import db

router = APIRouter()


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for live scan updates.

    Clients connect here to receive real-time events:
    - url_found, crawl_complete, finding, stage_changed, progress, scan_complete
    """
    await websocket.accept()
    scan_manager.register_ws(scan_id, websocket)

    # Send current state immediately if scan is active
    state = scan_manager.get_scan_state(scan_id)
    if state:
        await websocket.send_text(json.dumps({
            "event": "initial_state",
            "data": state.to_progress_dict(),
        }))
        # Send existing findings
        for finding in state.findings:
            await websocket.send_text(json.dumps({
                "event": "finding",
                "data": {
                    "finding": finding,
                    "findings_count": state.findings_count,
                    "severity_counts": state.severity_counts,
                },
            }))
    else:
        # Check if scan exists in DB (completed)
        scan_data = await db.get_scan(scan_id)
        if scan_data and scan_data.get("status") == "complete":
            await websocket.send_text(json.dumps({
                "event": "scan_complete",
                "data": {
                    "scan_id": scan_id,
                    "findings_count": scan_data.get("findings_count", 0),
                    "endpoints_count": scan_data.get("endpoints_count", 0),
                    "risk_score": scan_data.get("risk_score", 0),
                    "duration": scan_data.get("duration_seconds", 0),
                },
            }))

    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        scan_manager.unregister_ws(scan_id, websocket)
