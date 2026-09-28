"""CodexSIEM FastAPI application — routes and orchestration."""
from __future__ import annotations

import csv
import html
import io
import json
import logging
import subprocess
import traceback
from contextlib import closing
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import get_admin_credentials, hash_password, verify_password
from secret_utils import ENV_REF_PLACEHOLDER, resolve_client_secret
from startup_checks import run_startup_template_self_check

from codexsiem.config import (
    ALLOWED_ROLES,
    APP_TITLE,
    GITHUB_BRANCH,
    GITHUB_REPO,
    ROLE_ADMIN,
    ROLE_MANAGER,
    ROLE_USER,
    SESSION_HTTPS_ONLY,
    SESSION_SECRET,
    SSO_ENABLED,
    SSO_MFA_HEADER,
    SSO_REQUIRE_MFA,
    SSO_ROLE_HEADER,
    SSO_USER_HEADER,
    SYNC_MINUTES,
    TEMPLATES_DIR,
    validate_runtime_config,
)
from codexsiem.db import audit_log, db_conn, has_users, init_db, utc_now_iso
from codexsiem.detection import add_impossible_travel_reason, alert_reasons, severity_for_reason
from codexsiem.graph import fetch_signins, graph_token
from codexsiem.notifications import send_alert_email, send_openclawai_alert

LOGGER = logging.getLogger(__name__)

app = FastAPI(title=APP_TITLE)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=SESSION_HTTPS_ONLY,
)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def startup_template_self_check(strict: Optional[bool] = None) -> List[str]:
    return run_startup_template_self_check(
        env=templates.env, logger=LOGGER, templates_dir=TEMPLATES_DIR, strict=strict
    )


def _local_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=TEMPLATES_DIR.parent,
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
        return (
            f"Latest GitHub commit on {GITHUB_REPO}@{GITHUB_BRANCH}: "
            f"{remote_sha[:12]} (local git commit unavailable)."
        )

    if remote_sha and local_sha == remote_sha:
        return f"System is up to date with {GITHUB_REPO}@{GITHUB_BRANCH} ({local_sha[:12]})."

    return (
        f"Update available. Local: {local_sha[:12]} | GitHub: {remote_sha[:12]} "
        f"({GITHUB_REPO}@{GITHUB_BRANCH})."
    )


def user_can_manage(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_MANAGER}


def user_is_admin(role: str) -> bool:
    return role == ROLE_ADMIN


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
        audit_log(
            user,
            role,
            "sso_login",
            "denied",
            source_ip=request.client.host if request.client else "",
            details={"reason": "mfa_not_present"},
        )
        return

    request.session["user"] = user
    request.session["role"] = role
    audit_log(
        user,
        role,
        "sso_login",
        "success",
        source_ip=request.client.host if request.client else "",
    )


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


def persist_signins_and_alerts(tenant_id: str, signins: List[Dict[str, Any]]) -> int:
    import sqlite3

    ingested = 0
    with closing(db_conn()) as conn:
        customer_row = conn.execute(
            "SELECT customer_name FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        customer_name = (
            customer_row["customer_name"]
            if customer_row and customer_row["customer_name"]
            else "Unassigned"
        )

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
    results: Dict[str, Any] = {"tenants": 0, "ingested": 0, "errors": []}
    with closing(db_conn()) as conn:
        tenants = conn.execute("SELECT * FROM tenants ORDER BY name ASC").fetchall()

    for tenant in tenants:
        results["tenants"] += 1
        try:
            secret = resolve_client_secret(tenant)
            if not secret:
                raise ValueError(
                    f"Missing client secret. Set env var '{tenant['client_secret_ref']}' "
                    "or update tenant config."
                )
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


from pathlib import Path as _Path
_routes_path = _Path(__file__).resolve().parent / "codexsiem" / "_routes_src.py"
exec(compile(_routes_path.read_text(encoding="utf-8"), str(_routes_path), "exec"), globals())
