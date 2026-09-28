"""Alert email and OpenClaw webhook notifications."""
from __future__ import annotations

import logging
from email.message import EmailMessage
from typing import Any, Dict, Optional

import httpx
import smtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from codexsiem.config import (
    ALERT_EMAIL_ENABLED,
    ALERT_EMAIL_MIN_SEVERITY,
    OPENCLAWAI_API_KEY,
    OPENCLAWAI_ENABLED,
    OPENCLAWAI_TIMEOUT,
    OPENCLAWAI_URL,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO,
    SMTP_USE_SSL,
    SMTP_USE_TLS,
    SMTP_USER,
    TEMPLATES_DIR,
)

LOGGER = logging.getLogger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_alert_email_html(context: Dict[str, Any]) -> str:
    try:
        template = _env.get_template("alert_email.html")
        return template.render(**context)
    except Exception:
        LOGGER.exception("Failed to render alert_email.html")
        return ""


def email_config_status() -> Dict[str, Any]:
    """Return a non-secret summary of email configuration for UI/status checks."""
    missing = []
    if not ALERT_EMAIL_ENABLED:
        return {
            "enabled": False,
            "ready": False,
            "reason": "ALERT_EMAIL_ENABLED is not true",
            "recipients": len(SMTP_TO),
            "host": SMTP_HOST or None,
            "min_severity": ALERT_EMAIL_MIN_SEVERITY,
        }
    if not SMTP_HOST:
        missing.append("SMTP_HOST")
    if not SMTP_FROM:
        missing.append("SMTP_FROM")
    if not SMTP_TO:
        missing.append("SMTP_TO")
    return {
        "enabled": True,
        "ready": not missing,
        "reason": ("Missing: " + ", ".join(missing)) if missing else "ok",
        "recipients": len(SMTP_TO),
        "host": SMTP_HOST or None,
        "port": SMTP_PORT,
        "use_tls": SMTP_USE_TLS,
        "use_ssl": SMTP_USE_SSL,
        "min_severity": ALERT_EMAIL_MIN_SEVERITY,
        "has_auth": bool(SMTP_USER),
    }


def _severity_allowed(severity: str) -> bool:
    rank = _SEVERITY_RANK.get((severity or "").lower(), 0)
    min_rank = _SEVERITY_RANK.get(ALERT_EMAIL_MIN_SEVERITY.lower(), 1)
    return rank >= min_rank


def send_alert_email(subject: str, body: str, html_body: str = "") -> bool:
    """Send a multipart alert email. Returns True on success."""
    if not ALERT_EMAIL_ENABLED:
        return False
    if not SMTP_HOST or not SMTP_FROM or not SMTP_TO:
        LOGGER.warning("Alert email skipped: SMTP_HOST/FROM/TO not fully configured")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(SMTP_TO)
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        LOGGER.info("Alert email sent to %s: %s", SMTP_TO, subject)
        return True
    except Exception:
        LOGGER.exception("Failed to send alert email: %s", subject)
        return False


def notify_alert(payload: Dict[str, Any]) -> bool:
    """Render HTML + plain text and send if severity meets the minimum threshold."""
    severity = str(payload.get("severity") or "medium")
    if not _severity_allowed(severity):
        LOGGER.debug("Alert email skipped (severity %s below min %s)", severity, ALERT_EMAIL_MIN_SEVERITY)
        return False

    customer = payload.get("customer_name") or "Unassigned"
    tenant_id = payload.get("tenant_id") or ""
    reason = payload.get("reason") or ""
    subject = f"[CodexSIEM] {severity.upper()} · {customer} · {reason[:60]}"

    body = (
        f"CodexSIEM alert\n"
        f"Severity: {severity}\n"
        f"Customer: {customer}\n"
        f"Group: {payload.get('customer_group') or ''}\n"
        f"Tenant: {tenant_id}\n"
        f"User: {payload.get('user_principal_name') or ''}\n"
        f"IP: {payload.get('ip_address') or ''}\n"
        f"App: {payload.get('app_display_name') or ''}\n"
        f"Reason: {reason}\n"
        f"Sign-in time: {payload.get('signin_time') or ''}\n"
        f"Alert time: {payload.get('created_at') or ''}\n"
    )
    html_body = render_alert_email_html(
        {
            "severity": severity,
            "customer_name": customer,
            "customer_group": payload.get("customer_group") or "",
            "tenant_id": tenant_id,
            "user_principal_name": payload.get("user_principal_name") or "",
            "ip_address": payload.get("ip_address") or "",
            "app_display_name": payload.get("app_display_name") or "",
            "reason": reason,
            "created_at": payload.get("created_at") or "",
            "signin_time": payload.get("signin_time") or "",
        }
    )
    return send_alert_email(subject=subject, body=body, html_body=html_body)


def send_test_email(to_override: Optional[str] = None) -> Dict[str, Any]:
    """Send a test message to verify SMTP settings. Optionally override recipient."""
    status = email_config_status()
    if not status["enabled"]:
        return {"ok": False, "error": status["reason"]}
    if not status["ready"]:
        return {"ok": False, "error": status["reason"]}

    recipients = [to_override.strip()] if to_override and to_override.strip() else list(SMTP_TO)
    subject = "[CodexSIEM] Test email — configuration OK"
    body = (
        "This is a test message from CodexSIEM.\n"
        "If you received this, SMTP alerting is configured correctly.\n"
        f"Host: {SMTP_HOST}:{SMTP_PORT}\n"
        f"Min severity: {ALERT_EMAIL_MIN_SEVERITY}\n"
    )
    html = (
        "<p>This is a <strong>test message</strong> from CodexSIEM.</p>"
        "<p>If you received this, SMTP alerting is configured correctly.</p>"
    )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    msg.add_alternative(html, subtype="html")

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        LOGGER.info("Test email sent to %s", recipients)
        return {"ok": True, "recipients": recipients}
    except Exception as exc:
        LOGGER.exception("Test email failed")
        return {"ok": False, "error": str(exc)}


def send_openclawai_alert(payload: Dict[str, Any]) -> None:
    if not OPENCLAWAI_ENABLED or not OPENCLAWAI_URL:
        return
    headers = {"Content-Type": "application/json"}
    if OPENCLAWAI_API_KEY:
        headers["Authorization"] = f"Bearer {OPENCLAWAI_API_KEY}"
    try:
        httpx.post(OPENCLAWAI_URL, json=payload, headers=headers, timeout=OPENCLAWAI_TIMEOUT)
    except Exception:
        LOGGER.exception("OpenClawAI webhook failed")
