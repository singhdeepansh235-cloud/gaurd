"""Scan Manager — bridges the web UI to the Scanner core.

Manages scan lifecycle: start, monitor, stop, retrieve results.
Connects the Scanner's EventBus to WebSocket clients for real-time updates.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinal_fuzz.core.config import ScanConfig
from sentinal_fuzz.core.models import ScanResult
from sentinal_fuzz.scoring import calculate_scan_risk_score
from sentinal_fuzz.web.services import db


# ── Active scan state ──────────────────────────────────────────────

@dataclass
class ScanState:
    """Tracks the state of a running scan."""
    scan_id: str
    target: str
    profile: str
    status: str = "running"
    stage: str = "Initializing"
    start_time: float = field(default_factory=time.monotonic)

    # Crawl
    urls_found: int = 0
    forms_found: int = 0
    apis_found: int = 0
    current_url: str = ""

    # Fuzz
    endpoints_tested: int = 0
    endpoints_total: int = 0
    requests_sent: int = 0
    req_per_sec: float = 0.0

    # Findings
    findings: list[dict[str, Any]] = field(default_factory=list)
    findings_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })

    # Result
    result: ScanResult | None = None
    error: str | None = None

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    def to_progress_dict(self) -> dict[str, Any]:
        """Serialize current state for WebSocket broadcast."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "status": self.status,
            "stage": self.stage,
            "elapsed": round(self.elapsed_seconds(), 1),
            "crawl": {
                "urls_found": self.urls_found,
                "forms_found": self.forms_found,
                "apis_found": self.apis_found,
                "current_url": self.current_url,
            },
            "fuzz": {
                "endpoints_tested": self.endpoints_tested,
                "endpoints_total": self.endpoints_total,
                "requests_sent": self.requests_sent,
                "req_per_sec": round(self.req_per_sec, 1),
            },
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
        }


class ScanManager:
    """Manages active and completed scans for the web interface."""

    def __init__(self) -> None:
        self._active_scans: dict[str, ScanState] = {}
        self._tasks: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]
        self._ws_clients: dict[str, list[Any]] = {}  # scan_id → list of websocket connections

    # ── WebSocket management ───────────────────────────────────────

    def register_ws(self, scan_id: str, ws: Any) -> None:
        if scan_id not in self._ws_clients:
            self._ws_clients[scan_id] = []
        self._ws_clients[scan_id].append(ws)

    def unregister_ws(self, scan_id: str, ws: Any) -> None:
        if scan_id in self._ws_clients:
            try:
                self._ws_clients[scan_id].remove(ws)
            except ValueError:
                pass

    async def _broadcast(self, scan_id: str, event: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all WebSocket clients watching a scan."""
        msg = json.dumps({"event": event, "data": data})
        if scan_id not in self._ws_clients:
            return
        dead: list[Any] = []
        for ws in self._ws_clients[scan_id]:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister_ws(scan_id, ws)

    # ── Scan lifecycle ─────────────────────────────────────────────

    async def start_scan(self, config_dict: dict[str, Any]) -> ScanState:
        """Start a new scan from a config dictionary."""
        scan_id = uuid.uuid4().hex[:16]

        # Build ScanConfig
        config = ScanConfig.from_dict(config_dict)

        state = ScanState(
            scan_id=scan_id,
            target=config.target,
            profile=config.scan_profile,
        )
        self._active_scans[scan_id] = state

        # Save to DB
        await db.create_scan(scan_id, config.target, config.scan_profile, config_dict)

        # Run scan in background
        task = asyncio.create_task(self._run_scan(scan_id, config, state))
        self._tasks[scan_id] = task

        return state

    async def _run_scan(self, scan_id: str, config: ScanConfig, state: ScanState) -> None:
        """Execute the scan pipeline and broadcast events."""
        from sentinal_fuzz.core.scanner import Scanner

        scanner = Scanner(config=config)

        # ── Wire EventBus → WebSocket ──────────────────────────────
        api_count = 0

        def on_url_found(url: str = "", **_kw: object) -> None:
            nonlocal api_count
            state.urls_found += 1
            if "/api/" in url or url.endswith((".json", ".xml")):
                api_count += 1
                state.apis_found = api_count
            state.current_url = url
            asyncio.ensure_future(self._broadcast(scan_id, "url_found", {
                "url": url,
                "urls_found": state.urls_found,
                "apis_found": state.apis_found,
            }))

        def on_crawl_complete(endpoints: object = None, **_kw: object) -> None:
            if endpoints and isinstance(endpoints, list):
                state.endpoints_total = len(endpoints)
                state.forms_found = sum(
                    len(getattr(ep, "forms", [])) for ep in endpoints if hasattr(ep, "forms")
                )
                asyncio.ensure_future(self._broadcast(scan_id, "crawl_complete", {
                    "endpoints_total": state.endpoints_total,
                    "forms_found": state.forms_found,
                    "urls_found": state.urls_found,
                }))

        def on_finding(finding: object = None, **_kw: object) -> None:
            from sentinal_fuzz.core.models import Finding
            if finding and isinstance(finding, Finding):
                finding_dict = finding.to_dict()
                state.findings.append(finding_dict)
                state.findings_count += 1
                sev = finding.severity.value
                state.severity_counts[sev] = state.severity_counts.get(sev, 0) + 1
                asyncio.ensure_future(self._broadcast(scan_id, "finding", {
                    "finding": finding_dict,
                    "findings_count": state.findings_count,
                    "severity_counts": state.severity_counts,
                }))

        def on_stage_changed(stage: str = "", **_kw: object) -> None:
            state.stage = stage
            asyncio.ensure_future(self._broadcast(scan_id, "stage_changed", {
                "stage": stage,
            }))

        def on_fuzz_progress(
            endpoints_tested: int = 0,
            endpoints_total: int = 0,
            requests_sent: int = 0,
            current_url: str = "",
            **_kw: object,
        ) -> None:
            state.endpoints_tested = endpoints_tested
            state.endpoints_total = endpoints_total
            state.requests_sent = requests_sent
            state.current_url = current_url

        scanner.event_bus.on("url_found", on_url_found)
        scanner.event_bus.on("crawl_complete", on_crawl_complete)
        scanner.event_bus.on("finding", on_finding)
        scanner.event_bus.on("stage_changed", on_stage_changed)
        scanner.event_bus.on("fuzz_progress", on_fuzz_progress)

        # ── Periodic progress broadcast ───────────────────────────
        async def progress_loop() -> None:
            while state.status == "running":
                elapsed = state.elapsed_seconds()
                if elapsed > 0:
                    state.req_per_sec = state.requests_sent / elapsed
                await self._broadcast(scan_id, "progress", state.to_progress_dict())
                await asyncio.sleep(1.0)

        progress_task = asyncio.create_task(progress_loop())

        # ── Execute scan ──────────────────────────────────────────
        try:
            result = await scanner.run()
            state.result = result
            state.status = "complete"
            state.stage = "Complete ✓"
            state.requests_sent = result.stats.total_requests
            state.endpoints_tested = len(result.endpoints)
            state.endpoints_total = len(result.endpoints)

            # Reuse the shared scoring helper so risk stays consistent across APIs.
            risk = calculate_scan_risk_score(result.findings)

            # Save to DB
            await db.update_scan_result(
                scan_id=scan_id,
                result_dict=result.to_dict(),
                endpoints_count=len(result.endpoints),
                findings_count=len(result.findings),
                risk_score=risk,
                duration=result.duration_seconds,
            )

            await self._broadcast(scan_id, "scan_complete", {
                "scan_id": scan_id,
                "findings_count": len(result.findings),
                "endpoints_count": len(result.endpoints),
                "risk_score": risk,
                "duration": round(result.duration_seconds, 1),
                "severity_counts": state.severity_counts,
            })

        except asyncio.CancelledError:
            state.status = "cancelled"
            state.stage = "Cancelled"
            await db.update_scan_status(scan_id, "cancelled")
            await self._broadcast(scan_id, "scan_cancelled", {"scan_id": scan_id})

        except Exception as exc:
            state.status = "failed"
            state.stage = "Failed"
            state.error = str(exc)
            await db.update_scan_status(scan_id, "failed")
            await self._broadcast(scan_id, "scan_error", {
                "scan_id": scan_id,
                "error": str(exc),
            })

        finally:
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

    def get_scan_state(self, scan_id: str) -> ScanState | None:
        return self._active_scans.get(scan_id)

    async def stop_scan(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def is_scan_active(self, scan_id: str) -> bool:
        state = self._active_scans.get(scan_id)
        return state is not None and state.status == "running"


# Global instance
scan_manager = ScanManager()
