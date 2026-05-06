"""
SQLite persistence layer.

Stdlib sqlite3 only — no extra deps. Tables:
  engagement   client + scope + rules of engagement + tester identity
  scan         a single run against a target inside an engagement
  finding      individual finding, with raw req/resp/curl, fingerprint, status
  note         operator notes attached to a finding
  audit_log    append-only event stream (scan_started, http_request, status_change, ...)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

def _resolve_db_path() -> Path:
    """
    Pick a writable SQLite path for each runtime:
    - DB_PATH env var (explicit override)
    - Vercel serverless: /tmp is writable
    - local/dev: backend/cybersyc.db
    """
    env_path = os.getenv("DB_PATH")
    if env_path:
        return Path(env_path)
    if os.getenv("VERCEL") == "1":
        return Path(tempfile.gettempdir()) / "cybersyc.db"
    return Path(__file__).parent / "cybersyc.db"


DB_PATH = _resolve_db_path()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
  id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  contract_id TEXT,
  in_scope_targets TEXT NOT NULL,
  out_of_scope TEXT,
  rules_of_engagement TEXT,
  emergency_contact TEXT,
  tester_name TEXT NOT NULL,
  tester_email TEXT,
  loa_hash TEXT,
  window_start TEXT,
  window_end TEXT,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT
);

CREATE TABLE IF NOT EXISTS scan (
  id TEXT PRIMARY KEY,
  engagement_id TEXT REFERENCES engagement(id) ON DELETE SET NULL,
  target_url TEXT NOT NULL,
  profile TEXT NOT NULL DEFAULT 'standard',
  modules_run TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  cancelled_at TEXT,
  errors TEXT,
  summary TEXT
);

CREATE TABLE IF NOT EXISTS finding (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  tracking_id TEXT NOT NULL,
  module TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  cvss_score REAL DEFAULT 0,
  cvss_vector TEXT,
  cwe_id TEXT,
  cwe_name TEXT,
  description TEXT,
  evidence TEXT,
  evidence_request TEXT,
  evidence_response TEXT,
  evidence_curl TEXT,
  poc_steps TEXT,
  remediation TEXT,
  refs TEXT,
  target_url TEXT,
  fingerprint TEXT NOT NULL,
  confidence TEXT DEFAULT 'heuristic',
  epss REAL,
  kev INTEGER DEFAULT 0,
  status TEXT DEFAULT 'new',
  severity_override TEXT,
  severity_override_reason TEXT,
  discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS note (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  author TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  finding_id TEXT,
  engagement_id TEXT,
  event_type TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_scan ON finding(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_fp ON finding(fingerprint);
CREATE INDEX IF NOT EXISTS idx_finding_status ON finding(status);
CREATE INDEX IF NOT EXISTS idx_scan_engagement ON scan(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id);
"""


_lock = threading.RLock()


def _row_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Thread-safe connection context. Each call opens a new connection
    (sqlite3 connections aren't share-safe across threads by default)."""
    with _lock:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), isolation_level=None, timeout=30)
        conn.row_factory = _row_factory
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
        finally:
            conn.close()


def init_db() -> None:
    """Idempotent. Creates tables and indexes."""
    with connect() as conn:
        conn.executescript(_SCHEMA)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_json(v: Any) -> Optional[str]:
    if v is None:
        return None
    return json.dumps(v, ensure_ascii=False, default=str)


def _from_json(v: Any) -> Any:
    if v is None or v == "":
        return None
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return v


# -------- engagement --------

def insert_engagement(row: dict) -> None:
    cols = (
        "id", "client_name", "contract_id", "in_scope_targets", "out_of_scope",
        "rules_of_engagement", "emergency_contact", "tester_name", "tester_email",
        "loa_hash", "window_start", "window_end", "created_at", "status", "notes",
    )
    values = (
        row["id"], row["client_name"], row.get("contract_id"),
        _to_json(row.get("in_scope_targets") or []),
        _to_json(row.get("out_of_scope") or []),
        row.get("rules_of_engagement"), row.get("emergency_contact"),
        row["tester_name"], row.get("tester_email"),
        row.get("loa_hash"), row.get("window_start"), row.get("window_end"),
        row.get("created_at") or now_iso(),
        row.get("status") or "active",
        row.get("notes"),
    )
    with connect() as conn:
        conn.execute(
            f"INSERT INTO engagement ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            values,
        )


def get_engagement(eid: str) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM engagement WHERE id = ?", (eid,)).fetchone()
    if row:
        row["in_scope_targets"] = _from_json(row.get("in_scope_targets")) or []
        row["out_of_scope"] = _from_json(row.get("out_of_scope")) or []
    return row


def list_engagements() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM engagement ORDER BY created_at DESC"
        ).fetchall()
    for r in rows:
        r["in_scope_targets"] = _from_json(r.get("in_scope_targets")) or []
        r["out_of_scope"] = _from_json(r.get("out_of_scope")) or []
    return rows


def update_engagement_status(eid: str, status: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE engagement SET status = ? WHERE id = ?", (status, eid))


# -------- scan --------

def insert_scan(row: dict) -> None:
    cols = (
        "id", "engagement_id", "target_url", "profile", "modules_run",
        "status", "started_at", "completed_at", "cancelled_at", "errors", "summary",
    )
    values = (
        row["id"], row.get("engagement_id"), row["target_url"],
        row.get("profile") or "standard",
        _to_json(row.get("modules_run") or []),
        row.get("status") or "pending",
        row.get("started_at") or now_iso(),
        row.get("completed_at"), row.get("cancelled_at"),
        _to_json(row.get("errors") or []),
        _to_json(row.get("summary") or {}),
    )
    with connect() as conn:
        conn.execute(
            f"INSERT INTO scan ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            values,
        )


def update_scan(scan_id: str, **fields: Any) -> None:
    if not fields:
        return
    sets = []
    params: list[Any] = []
    for k, v in fields.items():
        if k in ("modules_run", "errors", "summary"):
            v = _to_json(v)
        sets.append(f"{k} = ?")
        params.append(v)
    params.append(scan_id)
    with connect() as conn:
        conn.execute(f"UPDATE scan SET {','.join(sets)} WHERE id = ?", params)


def get_scan(scan_id: str) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan WHERE id = ?", (scan_id,)).fetchone()
    if row:
        row["modules_run"] = _from_json(row.get("modules_run")) or []
        row["errors"] = _from_json(row.get("errors")) or []
        row["summary"] = _from_json(row.get("summary")) or {}
    return row


def list_scans(engagement_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    with connect() as conn:
        if engagement_id:
            rows = conn.execute(
                "SELECT * FROM scan WHERE engagement_id = ? ORDER BY started_at DESC LIMIT ?",
                (engagement_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    for r in rows:
        r["modules_run"] = _from_json(r.get("modules_run")) or []
        r["errors"] = _from_json(r.get("errors")) or []
        r["summary"] = _from_json(r.get("summary")) or {}
    return rows


def previous_scan_for_target(target_url: str, before_scan_id: str) -> Optional[dict]:
    """Most recent completed scan against the same target, before this one."""
    current = get_scan(before_scan_id)
    if not current:
        return None
    with connect() as conn:
        row = conn.execute(
            """SELECT * FROM scan
               WHERE target_url = ? AND id != ? AND status = 'completed'
                 AND started_at < ?
               ORDER BY started_at DESC LIMIT 1""",
            (target_url, before_scan_id, current["started_at"]),
        ).fetchone()
    if row:
        row["modules_run"] = _from_json(row.get("modules_run")) or []
        row["errors"] = _from_json(row.get("errors")) or []
        row["summary"] = _from_json(row.get("summary")) or {}
    return row


# -------- finding --------

_FINDING_COLS = (
    "id", "scan_id", "tracking_id", "module", "title", "severity",
    "cvss_score", "cvss_vector", "cwe_id", "cwe_name", "description",
    "evidence", "evidence_request", "evidence_response", "evidence_curl",
    "poc_steps", "remediation", "refs", "target_url", "fingerprint",
    "confidence", "epss", "kev", "status",
    "severity_override", "severity_override_reason", "discovered_at",
)


def insert_findings(rows: Iterable[dict]) -> None:
    payload = []
    for r in rows:
        payload.append((
            r["id"], r["scan_id"], r.get("tracking_id") or "",
            r["module"], r["title"], r["severity"],
            float(r.get("cvss_score") or 0), r.get("cvss_vector"),
            r.get("cwe_id"), r.get("cwe_name"), r.get("description"),
            r.get("evidence"), r.get("evidence_request"),
            r.get("evidence_response"), r.get("evidence_curl"),
            _to_json(r.get("poc_steps") or []), r.get("remediation"),
            _to_json(r.get("references") or r.get("refs") or []),
            r.get("target_url"), r.get("fingerprint") or "",
            r.get("confidence") or "heuristic",
            r.get("epss"), 1 if r.get("kev") else 0,
            r.get("status") or "new",
            r.get("severity_override"), r.get("severity_override_reason"),
            r.get("discovered_at") or now_iso(),
        ))
    with connect() as conn:
        conn.executemany(
            f"INSERT INTO finding ({','.join(_FINDING_COLS)}) "
            f"VALUES ({','.join('?' * len(_FINDING_COLS))})",
            payload,
        )


def _hydrate_finding(row: dict) -> dict:
    if not row:
        return row
    row["poc_steps"] = _from_json(row.get("poc_steps")) or []
    row["references"] = _from_json(row.get("refs")) or []
    row["kev"] = bool(row.get("kev"))
    row.pop("refs", None)
    return row


def get_finding(fid: str) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM finding WHERE id = ?", (fid,)).fetchone()
    return _hydrate_finding(row) if row else None


def list_findings_for_scan(scan_id: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM finding WHERE scan_id = ? ORDER BY cvss_score DESC, severity",
            (scan_id,),
        ).fetchall()
    return [_hydrate_finding(r) for r in rows]


def update_finding(fid: str, **fields: Any) -> None:
    if not fields:
        return
    sets = []
    params: list[Any] = []
    for k, v in fields.items():
        if k in ("poc_steps", "references"):
            sets.append(f"{'refs' if k == 'references' else k} = ?")
            params.append(_to_json(v))
        elif k == "kev":
            sets.append("kev = ?")
            params.append(1 if v else 0)
        else:
            sets.append(f"{k} = ?")
            params.append(v)
    params.append(fid)
    with connect() as conn:
        conn.execute(f"UPDATE finding SET {','.join(sets)} WHERE id = ?", params)


# -------- notes --------

def add_note(row: dict) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO note (id, finding_id, body, author, created_at) VALUES (?, ?, ?, ?, ?)",
            (row["id"], row["finding_id"], row["body"],
             row.get("author"), row.get("created_at") or now_iso()),
        )


def list_notes(finding_id: str) -> list[dict]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM note WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        ).fetchall()


# -------- audit log --------

def log_event(
    event_type: str,
    *,
    scan_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO audit_log (scan_id, finding_id, engagement_id,
                                       event_type, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_id, finding_id, engagement_id, event_type,
             _to_json(details or {}), now_iso()),
        )


def list_audit_events(
    scan_id: Optional[str] = None, limit: int = 500
) -> list[dict]:
    with connect() as conn:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE scan_id = ? ORDER BY id DESC LIMIT ?",
                (scan_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    for r in rows:
        r["details"] = _from_json(r.get("details")) or {}
    return rows
