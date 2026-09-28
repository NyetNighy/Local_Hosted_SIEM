"""CodexSIEM FastAPI application.

Preferred start:
  export SIEM_SESSION_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')
  python run_server.py
  # or: uvicorn application:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging
from contextlib import closing
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import get_admin_credentials
from startup_checks import run_startup_template_self_check

from codexsiem.config import (
    APP_TITLE,
    ROLE_ADMIN,
    SESSION_HTTPS_ONLY,
    SESSION_SECRET,
    TEMPLATES_DIR,
    validate_runtime_config,
)
from codexsiem.db import db_conn, has_users, init_db, utc_now_iso

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


def _load_routes() -> None:
    """Load full UI routes from codexsiem/_routes_src.py if present."""
    routes_path = Path(__file__).resolve().parent / "codexsiem" / "_routes_src.py"
    if not routes_path.exists() or routes_path.stat().st_size < 500:
        try:
            from codexsiem._routes_decode import ensure_routes_src

            routes_path = ensure_routes_src()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning(
                "Full UI routes not loaded (%s). Health endpoints still work. "
                "Restore codexsiem/_routes_src.py from the pre-refactor application.py routes.",
                exc,
            )
            return
    exec(compile(routes_path.read_text(encoding="utf-8"), str(routes_path), "exec"), globals())


_load_routes()
