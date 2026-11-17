"""SQLite persistence for scans, analyses and the scope allowlist."""

from __future__ import annotations

import json
import sqlite3
import time

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started REAL NOT NULL,
    finished REAL,
    exit_code INTEGER,
    argv TEXT,
    output TEXT NOT NULL DEFAULT '',
    analysis TEXT NOT NULL DEFAULT '',
    engine TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scope (
    root TEXT PRIMARY KEY,
    added REAL NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        # A scan left "running" by a crash or restart can never finish.
        conn.execute(
            "UPDATE scans SET status = 'interrupted', finished = COALESCE(finished, ?)"
            " WHERE status = 'running'",
            (time.time(),),
        )


def save_scan(scan: dict) -> None:
    with _conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (id, tool, tool_name, target, status, started, finished, exit_code,
                argv, output, analysis, engine)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan["id"], scan["tool"], scan["tool_name"], scan["target"],
                scan["status"], scan["started"], scan.get("finished"),
                scan.get("exit_code"),
                json.dumps(scan.get("argv") or []),
                scan.get("output") or "", scan.get("analysis") or "",
                scan.get("engine") or "",
            ),
        )


def list_scans(limit: int = 60) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            """SELECT id, tool, tool_name, target, status, started, finished,
                      exit_code, analysis != '' AS has_analysis
               FROM scans ORDER BY started DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    scan = dict(row)
    try:
        scan["argv"] = json.loads(scan.get("argv") or "[]")
    except json.JSONDecodeError:
        scan["argv"] = []
    return scan


def set_analysis(scan_id: str, text: str, engine: str) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE scans SET analysis = ?, engine = ? WHERE id = ?",
            (text, engine, scan_id),
        )


def scope_roots() -> list[str]:
    with _conn() as conn:
        rows = conn.execute("SELECT root FROM scope ORDER BY added").fetchall()
    return [row["root"] for row in rows]


def scope_add(root: str) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO scope (root, added) VALUES (?, ?)",
            (root, time.time()),
        )


def scope_remove(root: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM scope WHERE root = ?", (root,))
