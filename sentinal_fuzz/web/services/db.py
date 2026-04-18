"""SQLite database layer for scan history and settings.

Uses aiosqlite for async access. The database file is created
automatically in the project's data directory.
"""

from __future__ import annotations

import json
import aiosqlite
from pathlib import Path
from datetime import datetime
from typing import Any

_DB_PATH: Path | None = None
_DB_CONN: aiosqlite.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    profile TEXT DEFAULT 'standard',
    config_json TEXT,
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL DEFAULT 0,
    endpoints_count INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0,
    result_json TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def set_db_path(path: str | Path) -> None:
    global _DB_PATH
    _DB_PATH = Path(path)


def _get_db_path() -> Path:
    if _DB_PATH:
        return _DB_PATH
    # Default: store in project root
    default = Path.cwd() / "sentinal_fuzz_data" / "scans.db"
    default.parent.mkdir(parents=True, exist_ok=True)
    return default


async def get_db() -> aiosqlite.Connection:
    """Get or create a database connection."""
    global _DB_CONN
    if _DB_CONN is None:
        db_path = _get_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _DB_CONN = await aiosqlite.connect(str(db_path))
        _DB_CONN.row_factory = aiosqlite.Row
        await _DB_CONN.executescript(SCHEMA)
        await _DB_CONN.commit()
    return _DB_CONN


async def close_db() -> None:
    global _DB_CONN
    if _DB_CONN:
        await _DB_CONN.close()
        _DB_CONN = None


# ── Scan CRUD ──────────────────────────────────────────────────────

async def create_scan(
    scan_id: str,
    target: str,
    profile: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    db = await get_db()
    now = datetime.now().isoformat()
    await db.execute(
        """INSERT INTO scans (id, target, profile, config_json, status, started_at, created_at)
           VALUES (?, ?, ?, ?, 'running', ?, ?)""",
        (scan_id, target, profile, json.dumps(config), now, now),
    )
    await db.commit()
    return {"id": scan_id, "target": target, "profile": profile, "status": "running"}


async def update_scan_status(scan_id: str, status: str) -> None:
    db = await get_db()
    updates = {"status": status}
    if status in ("complete", "failed", "cancelled"):
        updates["completed_at"] = datetime.now().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [scan_id]
    await db.execute(f"UPDATE scans SET {set_clause} WHERE id = ?", values)
    await db.commit()


async def update_scan_result(
    scan_id: str,
    result_dict: dict[str, Any],
    endpoints_count: int,
    findings_count: int,
    risk_score: float,
    duration: float,
) -> None:
    db = await get_db()
    await db.execute(
        """UPDATE scans
           SET status = 'complete',
               completed_at = ?,
               result_json = ?,
               endpoints_count = ?,
               findings_count = ?,
               risk_score = ?,
               duration_seconds = ?
           WHERE id = ?""",
        (
            datetime.now().isoformat(),
            json.dumps(result_dict, default=str),
            endpoints_count,
            findings_count,
            risk_score,
            duration,
            scan_id,
        ),
    )
    await db.commit()


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def get_all_scans(limit: int = 50) -> list[dict[str, Any]]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT id, target, profile, status, started_at, completed_at, "
        "duration_seconds, endpoints_count, findings_count, risk_score, created_at "
        "FROM scans ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def delete_scan(scan_id: str) -> bool:
    conn = await get_db()
    # First check if the scan exists
    check = await conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,))
    row = await check.fetchone()
    if row is None:
        return False
    # Delete it
    await conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await conn.commit()
    return True


# ── Settings ───────────────────────────────────────────────────────

async def get_setting(key: str, default: str = "") -> str:
    db = await get_db()
    cursor = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = await cursor.fetchone()
    return row["value"] if row else default


async def set_setting(key: str, value: str) -> None:
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        (key, value),
    )
    await db.commit()


async def get_all_settings() -> dict[str, str]:
    db = await get_db()
    cursor = await db.execute("SELECT key, value FROM settings")
    rows = await cursor.fetchall()
    return {r["key"]: r["value"] for r in rows}
