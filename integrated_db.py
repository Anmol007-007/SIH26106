import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "integrated_security.db"
def get_db_connection() -> sqlite3.Connection:
    """Create and return a SQLite connection with Row factory."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection
def initialize_integrated_db():
    """Initialize the integrated security reports table."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE NOT NULL,
                message_id TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                received_at TEXT,
                raw_file_path TEXT NOT NULL,
                fraud_score INTEGER,
                category TEXT,
                confidence REAL,
                confidence_label TEXT,
                origin_ip TEXT,
                origin_country TEXT,
                origin_isp TEXT,
                trace_risk_score INTEGER,
                trace_risk_level TEXT,
                flags_json TEXT,
                full_report_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
def store_integrated_report(report: dict):
    """Store or update a unified security report in SQLite."""
    initialize_integrated_db()
    conn = get_db_connection()
    meta = report.get("message_meta", {})
    phish = report.get("phishing_detection", {})
    origin = report.get("origin_trace", {}).get("origin", {})
    origin_geo = origin.get("geo") or {}
    trace_risk = report.get("origin_trace", {}).get("risk", {})
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO security_reports (
                email_id,
                message_id,
                sender,
                recipient,
                subject,
                received_at,
                raw_file_path,
                fraud_score,
                category,
                confidence,
                confidence_label,
                origin_ip,
                origin_country,
                origin_isp,
                trace_risk_score,
                trace_risk_level,
                flags_json,
                full_report_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["email_id"],
                meta.get("message_id"),
                meta.get("from"),
                meta.get("to"),
                meta.get("subject"),
                meta.get("date"),
                report.get("raw_file_path", ""),
                phish.get("fraud_score"),
                phish.get("category"),
                phish.get("confidence"),
                phish.get("confidence_label"),
                origin.get("probable_source_ip"),
                origin_geo.get("country"),
                origin_geo.get("isp"),
                trace_risk.get("trace_risk_score"),
                trace_risk.get("trace_risk_level"),
                json.dumps(phish.get("flags", [])),
                json.dumps(report, default=str),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()
def fetch_all_reports() -> list[dict]:
    """Retrieve all stored security reports from SQLite."""
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM security_reports ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
