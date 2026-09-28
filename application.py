import csv
import html
import io
import logging
import json
import smtplib
import subprocess
import traceback
import os
import sqlite3
from pathlib import Path
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import get_admin_credentials, hash_password, verify_password
from secret_utils import ENV_REF_PLACEHOLDER, resolve_client_secret
from siem_core import alert_reasons
from startup_checks import run_startup_template_self_check

from codexsiem.config import validate_runtime_config
from codexsiem.detection import severity_for_reason

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

DB_PATH = os.getenv("SIEM_DB_PATH", "siem.db")
SYNC_MINUTES = int(os.getenv("SIEM_SYNC_MINUTES", "15"))
APP_TITLE = "M365 Multi-Tenant SIEM"
SESSION_SECRET = os.getenv("SIEM_SESSION_SECRET", "change-me-in-production")
SESSION_HTTPS_ONLY = os.getenv("SIEM_SESSION_HTTPS_ONLY", "false").lower() == "true"
OPENCLAWAI_ENABLED = os.getenv("OPENCLAWAI_ENABLED", "false").lower() == "true"
OPENCLAWAI_URL = os.getenv("OPENCLAWAI_URL", "").strip()
OPENCLAWAI_API_KEY = os.getenv("OPENCLAWAI_API_KEY", "").strip()
OPENCLAWAI_TIMEOUT = float(os.getenv("OPENCLAWAI_TIMEOUT", "10"))
GITHUB_REPO = os.getenv("SIEM_GITHUB_REPO", "").strip()
GITHUB_BRANCH = os.getenv("SIEM_GITHUB_BRANCH", "main").strip() or "main"

ALERT_EMAIL_ENABLED = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
SMTP_TO = [x.strip() for x in os.getenv("SMTP_TO", "").split(",") if x.strip()]
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

SSO_ENABLED = os.getenv("SIEM_SSO_ENABLED", "false").lower() == "true"
SSO_USER_HEADER = os.getenv("SIEM_SSO_USER_HEADER", "X-Auth-Request-User")
SSO_ROLE_HEADER = os.getenv("SIEM_SSO_ROLE_HEADER", "X-Auth-Request-Role")
SSO_MFA_HEADER = os.getenv("SIEM_SSO_MFA_HEADER", "X-Auth-Request-Amr")
SSO_REQUIRE_MFA = os.getenv("SIEM_SSO_REQUIRE_MFA", "true").lower() == "true"

ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_USER = "user"
ALLOWED_ROLES = {ROLE_ADMIN, ROLE_MANAGER, ROLE_USER}

app = FastAPI(title=APP_TITLE)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=SESSION_HTTPS_ONLY)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
LOGGER = logging.getLogger(__name__)


def startup_template_self_check(strict: Optional[bool] = None) -> List[str]:
    return run_startup_template_self_check(env=templates.env, logger=LOGGER, templates_dir=TEMPLATES_DIR, strict=strict)


def _local_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=BASE_DIR,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def check_github_update_status() -> str:
    if not GITHUB_REPO:
        return "Update check is not configured. Set SIEM_GITHUB_REPO (example: owner/repo)."

    try:
        resp = httpx.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/commits/{GITHUB_BRANCH}",
            timeout=10,
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        remote_sha = (resp.json() or {}).get("sha", "")
    except Exception as exc:  # noqa: BLE001
        return f"GitHub update check failed: {exc}"

    local_sha = _local_git_commit()
    if not local_sha:
        return f"Latest GitHub commit on {GITHUB_REPO}@{GITHUB_BRANCH}: {remote_sha[:12]} (local git commit unavailable)."

    if remote_sha and local_sha == remote_sha:
        return f"System is up to date with {GITHUB_REPO}@{GITHUB_BRANCH} ({local_sha[:12]})."

    return f"Update available. Local: {local_sha[:12]} | GitHub: {remote_sha[:12]} ({GITHUB_REPO}@{GITHUB_BRANCH})."


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(db_conn()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                customer_name TEXT NOT NULL DEFAULT 'Unassigned',
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
            """
        )
        conn.commit()

        cols = [row[1] for row in conn.execute("PRAGMA table_info(tenants)").fetchall()]
        if "client_secret_ref" not in cols:
            conn.execute("ALTER TABLE tenants ADD COLUMN client_secret_ref TEXT")
        if "customer_name" not in cols:
            conn.execute("ALTER TABLE tenants ADD COLUMN customer_name TEXT NOT NULL DEFAULT 'Unassigned'")

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


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def has_users() -> bool:
    with closing(db_conn()) as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def user_can_manage(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_MANAGER}


def user_is_admin(role: str) -> bool:
    return role == ROLE_ADMIN


def audit_log(
    actor: str,
    actor_role: str,
    action: str,
    outcome: str,
    target: str = "",
    source_ip: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> None:
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


def maybe_session_from_sso(request: Request) -> None:
    if not SSO_ENABLED:
        return
    if request.session.get("user") and request.session.get("role"):
        return

    user = request.headers.get(SSO_USER_HEADER, "").strip()
    role = request.headers.get(SSO_ROLE_HEADER, ROLE_USER).strip().lower() or ROLE_USER
    amr = request.headers.get(SSO_MFA_HEADER, "").lower()

    if not user:
        return
    if role not in ALLOWED_ROLES:
        role = ROLE_USER

    if SSO_REQUIRE_MFA and "mfa" not in amr:
        audit_log(user, role, "sso_login", "denied", source_ip=request.client.host if request.client else "", details={"reason": "mfa_not_present"})
        return

    request.session["user"] = user
    request.session["role"] = role
    audit_log(user, role, "sso_login", "success", source_ip=request.client.host if request.client else "")


def require_login(request: Request) -> Optional[RedirectResponse]:
    if not has_users():
        return RedirectResponse(url="/setup", status_code=303)

    maybe_session_from_sso(request)
    if request.session.get("user") and request.session.get("role"):
        return None
    return RedirectResponse(url="/login", status_code=303)


def require_manage_access(request: Request) -> Optional[RedirectResponse]:
    auth = require_login(request)
    if auth:
        return auth
    if user_can_manage(request.session.get("role", "")):
        return None
    return RedirectResponse(url="/?error=Insufficient+permissions", status_code=303)


def require_admin_access(request: Request) -> Optional[RedirectResponse]:
    auth = require_login(request)
    if auth:
        return auth
    if user_is_admin(request.session.get("role", "")):
        return None
    return RedirectResponse(url="/?error=Admin+access+required", status_code=303)


def bootstrap_admin_user() -> None:
    admin_user, salt_hex, digest_hex = get_admin_credentials()
    if not salt_hex or not digest_hex:
        return

    with closing(db_conn()) as conn:
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            conn.execute(
                """
                INSERT INTO users (username, role, password_salt, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (admin_user, ROLE_ADMIN, salt_hex, digest_hex, utc_now_iso()),
            )
            conn.commit()


async def graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, data=data)
        response.raise_for_status()
        return response.json()["access_token"]


async def fetch_signins(token: str, lookback_minutes: int = 60) -> List[Dict[str, Any]]:
    since = (datetime.now(tz=timezone.utc) - timedelta(minutes=lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    params = {"$filter": f"createdDateTime ge {since}", "$top": "100"}
    headers = {"Authorization": f"Bearer {token}"}
    records: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=30) as client:
        next_url: Optional[str] = url
        while next_url:
            response = await client.get(next_url, headers=headers, params=params if next_url == url else None)
            response.raise_for_status()
            page = response.json()
            records.extend(page.get("value", []))
            next_url = page.get("@odata.nextLink")

    return records


def render_alert_email_html(context: Dict[str, Any]) -> str:
    try:
        template = templates.env.get_template("alert_email.html")
        return template.render(**context)
    except Exception:
        return ""


def send_alert_email(subject: str, body: str, html_body: str = "") -> None:
    if not ALERT_EMAIL_ENABLED:
        return
    if not SMTP_HOST or not SMTP_FROM or not SMTP_TO:
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(SMTP_TO)
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception:
        return


def send_openclawai_alert(payload: Dict[str, Any]) -> None:
    if not OPENCLAWAI_ENABLED or not OPENCLAWAI_URL:
        return
    headers = {"Content-Type": "application/json"}
    if OPENCLAWAI_API_KEY:
        headers["Authorization"] = f"Bearer {OPENCLAWAI_API_KEY}"
    try:
        httpx.post(OPENCLAWAI_URL, json=payload, headers=headers, timeout=OPENCLAWAI_TIMEOUT)
    except Exception:
        return


def add_impossible_travel_reason(conn: sqlite3.Connection, tenant_id: str, signin: Dict[str, Any]) -> List[str]:
    upn = signin.get("userPrincipalName")
    created = signin.get("createdDateTime")
    location = signin.get("location") or {}
    country = (location.get("countryOrRegion") or "").strip()
    if not upn or not created or not country:
        return []

    row = conn.execute(
        """
        SELECT created_at, location_country
        FROM signins
        WHERE tenant_id = ? AND user_principal_name = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id, upn),
    ).fetchone()
    if not row or not row["location_country"]:
        return []

    try:
        prev_time = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
        cur_time = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return []

    if row["location_country"] != country and abs((cur_time - prev_time).total_seconds()) < 3600:
        return [
            f"Possible impossible travel: user moved from {row['location_country']} to {country} within 60 minutes"
        ]
    return []


def persist_signins_and_alerts(tenant_id: str, signins: List[Dict[str, Any]]) -> int:
    ingested = 0
    with closing(db_conn()) as conn:
        customer_row = conn.execute("SELECT customer_name FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
        customer_name = customer_row["customer_name"] if customer_row and customer_row["customer_name"] else "Unassigned"

        for signin in signins:
            graph_id = signin.get("id")
            if not graph_id:
                continue

            status = signin.get("status") or {}
            location = signin.get("location") or {}
            try:
                conn.execute(
                    """
                    INSERT INTO signins (
                        tenant_id, graph_id, created_at, user_principal_name, ip_address,
                        app_display_name, status_error_code, status_failure_reason,
                        conditional_access_status, location_country, location_city, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant_id,
                        graph_id,
                        signin.get("createdDateTime"),
                        signin.get("userPrincipalName"),
                        signin.get("ipAddress"),
                        signin.get("appDisplayName"),
                        status.get("errorCode"),
                        status.get("failureReason"),
                        signin.get("conditionalAccessStatus"),
                        location.get("countryOrRegion"),
                        location.get("city"),
                        json.dumps(signin, ensure_ascii=False, default=str),
                    ),
                )
                ingested += 1
            except sqlite3.IntegrityError:
                continue

            reasons = alert_reasons(signin)
            reasons.extend(add_impossible_travel_reason(conn, tenant_id, signin))

            for reason in reasons:
                severity = severity_for_reason(reason)
                created_at = utc_now_iso()
                try:
                    conn.execute(
                        """
                        INSERT INTO alerts (tenant_id, signins_graph_id, severity, reason, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (tenant_id, graph_id, severity, reason, created_at),
                    )
                except sqlite3.IntegrityError:
                    continue
                payload = {
                    "source": "codexsiem",
                    "tenant_id": tenant_id,
                    "customer_name": customer_name,
                    "signins_graph_id": graph_id,
                    "severity": severity,
                    "reason": reason,
                    "created_at": created_at,
                    "user_principal_name": signin.get("userPrincipalName"),
                    "ip_address": signin.get("ipAddress"),
                    "app_display_name": signin.get("appDisplayName"),
                    "signin_time": signin.get("createdDateTime"),
                    "status": signin.get("status") or {},
                }
                send_openclawai_alert(payload)
                send_alert_email(
                    subject=f"[CodexSIEM] {severity.upper()} alert for {tenant_id}",
                    body=(
                        f"Customer: {customer_name}\n"
                        f"Tenant: {tenant_id}\n"
                        f"User: {signin.get('userPrincipalName')}\n"
                        f"IP: {signin.get('ipAddress')}\n"
                        f"App: {signin.get('appDisplayName')}\n"
                        f"Reason: {reason}\n"
                        f"Time: {created_at}"
                    ),
                )

        conn.commit()
    return ingested


async def sync_all_tenants() -> Dict[str, Any]:
    results = {"tenants": 0, "ingested": 0, "errors": []}
    with closing(db_conn()) as conn:
        tenants = conn.execute("SELECT * FROM tenants ORDER BY name ASC").fetchall()

    for tenant in tenants:
        results["tenants"] += 1
        try:
            secret = resolve_client_secret(tenant)
            if not secret:
                raise ValueError(f"Missing client secret. Set env var '{tenant['client_secret_ref']}' or update tenant config.")
            token = await graph_token(tenant["tenant_id"], tenant["client_id"], secret)
            signins = await fetch_signins(token, lookback_minutes=SYNC_MINUTES)
            results["ingested"] += persist_signins_and_alerts(tenant["tenant_id"], signins)
        except Exception as exc:  # noqa: BLE001
            results["errors"].append(f"{tenant['name']}: {exc}")
    return results


@app.on_event("startup")
async def startup() -> None:
    validate_runtime_config()
    startup_template_self_check()
    init_db()
    bootstrap_admin_user()


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/ready")
async def ready() -> JSONResponse:
    try:
        with closing(db_conn()) as conn:
            conn.execute("SELECT 1").fetchone()
        return JSONResponse({"status": "ready"})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"status": "not_ready", "error": str(exc)}, status_code=503)
