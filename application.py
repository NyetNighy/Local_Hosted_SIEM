"""CodexSIEM FastAPI application.

Start:
  export SIEM_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  python run_server.py
"""
from __future__ import annotations

import csv
import html
import io
import json
import logging
import subprocess
import traceback
from contextlib import closing
from typing import Any, Dict, List, Optional, Tuple

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
    DETECTION_RULES_PATH,
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
from codexsiem.db import (
    audit_log,
    db_conn,
    get_tenant_watermark,
    has_users,
    init_db,
    sync_status_summary,
    update_tenant_sync,
    utc_now_iso,
)
from codexsiem.detection import evaluate_alerts
from codexsiem.graph import fetch_signins, graph_token
from codexsiem.notifications import notify_alert, send_openclawai_alert, webhook_config_status
from codexsiem.rules_engine import rules_status

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
    except Exception:
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
    except Exception as exc:
        return f"GitHub update check failed: {exc}"
    local_sha = _local_git_commit()
    if not local_sha:
        return f"Latest GitHub commit on {GITHUB_REPO}@{GITHUB_BRANCH}: {remote_sha[:12]} (local git commit unavailable)."
    if remote_sha and local_sha == remote_sha:
        return f"System is up to date with {GITHUB_REPO}@{GITHUB_BRANCH} ({local_sha[:12]})."
    return f"Update available. Local: {local_sha[:12]} | GitHub: {remote_sha[:12]} ({GITHUB_REPO}@{GITHUB_BRANCH})."


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


def persist_signins_and_alerts(tenant_id: str, signins: List[Dict[str, Any]]) -> Tuple[int, Optional[str]]:
    """Ingest sign-ins and fire alerts. Returns (ingested_count, max_event_createdDateTime)."""
    import sqlite3

    ingested = 0
    max_event: Optional[str] = None
    with closing(db_conn()) as conn:
        customer_row = conn.execute(
            "SELECT customer_name, customer_group FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        customer_name = (
            customer_row["customer_name"]
            if customer_row and customer_row["customer_name"]
            else "Unassigned"
        )
        customer_group = (
            customer_row["customer_group"]
            if customer_row and customer_row["customer_group"]
            else ""
        )
        for signin in signins:
            graph_id = signin.get("id")
            if not graph_id:
                continue
            created = signin.get("createdDateTime")
            if created and (max_event is None or str(created) > max_event):
                max_event = str(created)
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
                        created,
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
                # Already stored — still advance watermark but do not re-alert
                continue

            alerts = evaluate_alerts(signin, tenant_id, conn)
            for hit in alerts:
                severity = hit.get("severity") or "medium"
                reason = hit.get("reason") or hit.get("name") or "alert"
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
                    "customer_group": customer_group,
                    "signins_graph_id": graph_id,
                    "severity": severity,
                    "reason": reason,
                    "rule_id": hit.get("rule_id") or "",
                    "rule_group": hit.get("group") or "",
                    "created_at": created_at,
                    "user_principal_name": signin.get("userPrincipalName"),
                    "ip_address": signin.get("ipAddress"),
                    "app_display_name": signin.get("appDisplayName"),
                    "signin_time": created,
                    "status": signin.get("status") or {},
                }
                send_openclawai_alert(payload)
                if hit.get("notify", True):
                    notify_alert(payload)
        conn.commit()
    return ingested, max_event


async def sync_all_tenants() -> Dict[str, Any]:
    results: Dict[str, Any] = {"tenants": 0, "ingested": 0, "errors": []}
    with closing(db_conn()) as conn:
        tenants = conn.execute("SELECT * FROM tenants ORDER BY name ASC").fetchall()
    for tenant in tenants:
        results["tenants"] += 1
        tid = tenant["tenant_id"]
        try:
            secret = resolve_client_secret(tenant)
            if not secret:
                raise ValueError(
                    f"Missing client secret. Set env var '{tenant['client_secret_ref']}' or update tenant config."
                )
            token = await graph_token(tid, tenant["client_id"], secret)
            watermark = get_tenant_watermark(tid)
            signins = await fetch_signins(
                token, lookback_minutes=SYNC_MINUTES, since_watermark=watermark
            )
            count, max_event = persist_signins_and_alerts(tid, signins)
            results["ingested"] += count
            update_tenant_sync(tid, status="ok", error="", watermark=max_event or watermark)
        except Exception as exc:
            results["errors"].append(f"{tenant['name']}: {exc}")
            update_tenant_sync(tid, status="error", error=str(exc)[:500])
    return results


@app.on_event("startup")
async def startup() -> None:
    validate_runtime_config()
    startup_template_self_check()
    init_db()
    bootstrap_admin_user()
    status = rules_status(DETECTION_RULES_PATH)
    if status.get("ok"):
        LOGGER.info(
            "Detection rules ready: %s rules from %s",
            status.get("rule_count"),
            status.get("path"),
        )
    else:
        LOGGER.warning("Detection rules not loaded: %s", status.get("error"))


@app.get("/health")
async def health() -> JSONResponse:
    sync = sync_status_summary()
    return JSONResponse(
        {
            "status": "ok",
            "rules": rules_status(),
            "webhooks": webhook_config_status(),
            "sync": {
                "tenant_count": sync["tenant_count"],
                "ok": sync["ok"],
                "failed": sync["failed"],
                "never_synced": sync["never_synced"],
                "oldest_sync_at": sync["oldest_sync_at"],
                "newest_sync_at": sync["newest_sync_at"],
            },
        }
    )


@app.get("/ready")
async def ready() -> JSONResponse:
    try:
        with closing(db_conn()) as conn:
            conn.execute("SELECT 1").fetchone()
        return JSONResponse({"status": "ready"})
    except Exception as exc:
        return JSONResponse({"status": "not_ready", "error": str(exc)}, status_code=503)


def _load_routes() -> None:
    from codexsiem._routes_assemble import ensure_routes_src

    routes_path = ensure_routes_src()
    exec(compile(routes_path.read_text(encoding="utf-8"), str(routes_path), "exec"), globals())


_load_routes()
