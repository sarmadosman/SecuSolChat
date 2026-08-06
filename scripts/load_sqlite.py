#!/usr/bin/env python3
"""Load the JSON fixtures into a SQLite database.

Exists so the SQL path can be exercised for real — same behavioural tests as the
mock client, run against an actual database with actual bound parameters — long
before MTC's real one is available.

    python3 scripts/load_sqlite.py
    USE_SQL=true SQL_DSN=sqlite:///data/security.db streamlit run app.py

The columns here deliberately match `sql_schema.DEFAULT_SCHEMA`. A real database
will not: edit `security_client/sql_schema.py` to map their names onto these,
rather than renaming anything in the application.

⚠️ **The application account must be read-only.** SqlSecurityClient opens SQLite
with `mode=ro` and refuses non-SELECT statements, but application-level checks
are the last line of defence, not the first. On a real server, create a role that
can only SELECT the four tables:

    CREATE ROLE chatbot_ro LOGIN PASSWORD '...';
    GRANT SELECT ON alarms, events, logs, devices TO chatbot_ro;

Then even a total compromise of this process cannot write.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "security.db"

# Only the columns the assistant is allowed to read. The sensitive fields in the
# JSON fixtures (usernames, IPs, badge IDs, tokens) are intentionally NOT loaded:
# a real deployment should prefer a database view that excludes them, so the
# application account cannot select what it must not show.
SCHEMA = """
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    category    TEXT NOT NULL,
    area        TEXT,
    status      TEXT NOT NULL,
    last_seen   TEXT,
    firmware    TEXT
);
CREATE TABLE alarms (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    type        TEXT NOT NULL,
    message     TEXT,
    device_id   TEXT,
    device_name TEXT,
    device_type TEXT,
    category    TEXT,
    area        TEXT
);
CREATE TABLE events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    type        TEXT NOT NULL,
    outcome     TEXT,
    message     TEXT,
    device_id   TEXT,
    device_name TEXT,
    device_type TEXT,
    category    TEXT,
    area        TEXT
);
CREATE TABLE logs (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    level       TEXT NOT NULL,
    component   TEXT,
    message     TEXT,
    device_id   TEXT,
    device_name TEXT,
    device_type TEXT,
    category    TEXT,
    area        TEXT
);
-- Without these, a broad question table-scans. On a real log table this is the
-- difference between a fast answer and a stalled monitoring database.
CREATE INDEX idx_alarms_time     ON alarms(timestamp DESC);
CREATE INDEX idx_alarms_status   ON alarms(status, severity);
CREATE INDEX idx_alarms_device   ON alarms(device_id);
CREATE INDEX idx_events_time     ON events(timestamp DESC);
CREATE INDEX idx_events_device   ON events(device_id, type);
CREATE INDEX idx_logs_time       ON logs(timestamp DESC);
CREATE INDEX idx_logs_device     ON logs(device_id, level);
CREATE INDEX idx_devices_status  ON devices(status, category);
"""

COLUMNS = {
    "devices": ["id", "name", "type", "category", "area", "status", "last_seen", "firmware"],
    "alarms": ["id", "timestamp", "severity", "status", "type", "message",
               "device_id", "device_name", "device_type", "category", "area"],
    "events": ["id", "timestamp", "type", "outcome", "message",
               "device_id", "device_name", "device_type", "category", "area"],
    "logs": ["id", "timestamp", "level", "component", "message",
             "device_id", "device_name", "device_type", "category", "area"],
}


def build(db_path: Path = DB_PATH, data_dir: Path = DATA_DIR) -> Path:
    missing = [n for n in COLUMNS if not (data_dir / f"{n}.json").exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing fixtures {missing}. Run: python3 scripts/generate_fixtures.py"
        )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.unlink(missing_ok=True)

    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(SCHEMA)
        for table, columns in COLUMNS.items():
            rows = json.loads((data_dir / f"{table}.json").read_text())
            placeholders = ", ".join("?" for _ in columns)
            connection.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                [tuple(row.get(column) for column in columns) for row in rows],
            )
            print(f"{table}: {len(rows)} rows")
        connection.commit()
    finally:
        connection.close()
    return db_path


if __name__ == "__main__":
    path = build()
    print(f"\nWrote {path.relative_to(ROOT)}")
    print(f"Run with:  USE_SQL=true SQL_DSN=sqlite:///{path.relative_to(ROOT)} streamlit run app.py")
    sys.exit(0)
