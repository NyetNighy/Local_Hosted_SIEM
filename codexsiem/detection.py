"""Sign-in detection / alerting rules."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Dict, List


LEGACY_AUTH_CLIENTS = {
    "imap4",
    "pop3",
    "smtp",
    "exchange activesync",
    "other clients",
}

HIGH_RISK_COUNTRIES = {"RU", "KP", "IR"}


def alert_reasons(signin: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    status = signin.get("status") or {}
    err = status.get("errorCode")
    if isinstance(err, int) and err != 0:
        reasons.append(f"Failed sign-in (error code {err})")

    risk_level = signin.get("riskLevelDuringSignIn")
    if risk_level and str(risk_level).lower() not in {"none", "hidden", "null"}:
        reasons.append(f"Risk level during sign-in: {risk_level}")

    cas = signin.get("conditionalAccessStatus")
    if cas and str(cas).lower() in {"failure", "notapplied"}:
        reasons.append(f"Conditional access status: {cas}")

    client_app = str(signin.get("clientAppUsed") or "").lower()
    if client_app in LEGACY_AUTH_CLIENTS:
        reasons.append(f"Legacy authentication client used: {signin.get('clientAppUsed')}")

    location = signin.get("location") or {}
    country = location.get("countryOrRegion")
    if country and str(country).strip().upper() in HIGH_RISK_COUNTRIES:
        reasons.append(f"Sign-in from monitored high-risk country: {country}")

    return reasons


def severity_for_reason(reason: str) -> str:
    high_markers = ("Failed", "Risk", "impossible travel")
    return "high" if any(x in reason for x in high_markers) else "medium"


def add_impossible_travel_reason(
    conn: sqlite3.Connection, tenant_id: str, signin: Dict[str, Any]
) -> List[str]:
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
