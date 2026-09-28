"""Alert email and OpenClaw webhook notifications."""
from __future__ import annotations

from email.message import EmailMessage
from typing import Any, Dict

import httpx
import smtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from codexsiem.config import (
    ALERT_EMAIL_ENABLED,
    OPENCLAWAI_API_KEY,
    OPENCLAWAI_ENABLED,
    OPENCLAWAI_TIMEOUT,
    OPENCLAWAI_URL,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO,
    SMTP_USE_TLS,
    SMTP_USER,
    TEMPLATES_DIR,
)

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_alert_email_html(context: Dict[str, Any]) -> str:
    try:
        template = _env.get_template("alert_email.html")
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
