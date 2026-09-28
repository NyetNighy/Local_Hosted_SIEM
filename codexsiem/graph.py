"""Microsoft Graph client helpers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from codexsiem.config import SYNC_MINUTES


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


def _normalize_since(watermark: Optional[str], lookback_minutes: int) -> str:
    """Pick the later of (now - lookback) and watermark, formatted for Graph filter."""
    floor = datetime.now(tz=timezone.utc) - timedelta(minutes=lookback_minutes)
    since_dt = floor
    if watermark:
        s = str(watermark).strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            wm = datetime.fromisoformat(s)
            if wm.tzinfo is None:
                wm = wm.replace(tzinfo=timezone.utc)
            # Add 1 second so we do not re-fetch the last event
            wm = wm + timedelta(seconds=1)
            if wm > since_dt:
                since_dt = wm
        except ValueError:
            pass
    return since_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def fetch_signins(
    token: str,
    lookback_minutes: int = SYNC_MINUTES,
    since_watermark: Optional[str] = None,
) -> List[Dict[str, Any]]:
    since = _normalize_since(since_watermark, lookback_minutes)
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    params = {"$filter": f"createdDateTime ge {since}", "$top": "100"}
    headers = {"Authorization": f"Bearer {token}"}
    records: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=30) as client:
        next_url: Optional[str] = url
        while next_url:
            response = await client.get(
                next_url, headers=headers, params=params if next_url == url else None
            )
            response.raise_for_status()
            page = response.json()
            records.extend(page.get("value", []))
            next_url = page.get("@odata.nextLink")

    return records
