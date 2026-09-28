"""Application configuration from environment variables."""
from __future__ import annotations

import os
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

DB_PATH = os.getenv("SIEM_DB_PATH", "siem.db")
SYNC_MINUTES = int(os.getenv("SIEM_SYNC_MINUTES", "15"))
APP_TITLE = os.getenv("SIEM_APP_TITLE", "M365 Multi-Tenant SIEM")

_DEFAULT_SESSION_SECRET = "change-me-in-production"
SESSION_SECRET = os.getenv("SIEM_SESSION_SECRET", _DEFAULT_SESSION_SECRET)
SESSION_HTTPS_ONLY = os.getenv("SIEM_SESSION_HTTPS_ONLY", "false").lower() == "true"
ALLOW_INSECURE = os.getenv("SIEM_ALLOW_INSECURE", "false").lower() == "true"

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


def validate_runtime_config() -> None:
    """Refuse insecure defaults unless explicitly allowed for local demos."""
    if SESSION_SECRET == _DEFAULT_SESSION_SECRET and not ALLOW_INSECURE:
        print(
            "ERROR: SIEM_SESSION_SECRET is unset or using the insecure default.\n"
            "Set a strong random value, e.g.:\n"
            '  export SIEM_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")\n'
            "For local demos only, set SIEM_ALLOW_INSECURE=true.",
            file=sys.stderr,
        )
        raise SystemExit(1)
