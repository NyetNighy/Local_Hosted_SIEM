"""SQLite database helpers and schema."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from codexsiem.config import DB_PATH


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def init_db() -> None:
    with closing(db_conn()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                customer_name TEXT NOT NULL DEFAULT 'Unassigned',
                customer_group TEXT NOT NULL DEFAULT '',
                tenant_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                client_secret_ref TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                graph_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_principal_name TEXT,
                ip_address TEXT,
                app_display_name TEXT,
                status_error_code INTEGER,
                status_failure_reason TEXT,
                conditional_access_status TEXT,
                location_country TEXT,
                location_city TEXT,
                raw_json TEXT NOT NULL,
                UNIQUE(tenant_id, graph_id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                signins_graph_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(tenant_id, signins_graph_id, reason)
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                CHECK(role IN ('admin', 'manager', 'user'))
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                outcome TEXT NOT NULL,
                source_ip TEXT,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

        cols = [row[1] for row in conn.execute("PRAGMA table_info(tenants)").fetchall()]
        if "client_secret_ref" not in cols:
            conn.execute("ALTER TABLE tenants ADD COLUMN client_secret_ref TEXT")
        if "customer_name" not in cols:
            conn.execute(
                "ALTER TABLE tenants ADD COLUMN customer_name TEXT NOT NULL DEFAULT 'Unassigned'"
            )
        if "customer_group" not in cols:
            conn.execute(
                "ALTER TABLE tenants ADD COLUMN customer_group TEXT NOT NULL DEFAULT ''"
            )

        signins_cols = [row[1] for row in conn.execute("PRAGMA table_info(signins)").fetchall()]
        if "location_country" not in signins_cols:
            conn.execute("ALTER TABLE signins ADD COLUMN location_country TEXT")
        if "location_city" not in signins_cols:
            conn.execute("ALTER TABLE signins ADD COLUMN location_city TEXT")

        try:
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique
                ON alerts (tenant_id, signins_graph_id, reason)
                """
            )
        except sqlite3.OperationalError:
            pass

        conn.commit()


def has_users() -> bool:
    with closing(db_conn()) as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def audit_log(
    actor: str,
    actor_role: str,
    action: str,
    outcome: str,
    target: str = "",
    source_ip: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    import json

    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (event_time, actor, actor_role, action, target, outcome, source_ip, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                actor or "unknown",
                actor_role or "unknown",
                action,
                target,
                outcome,
                source_ip,
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )
        conn.commit()
