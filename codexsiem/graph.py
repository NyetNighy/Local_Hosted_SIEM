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


async def fetch_signins(token: str, lookback_minutes: int = SYNC_MINUTES) -> List[Dict[str, Any]]:
    since = (datetime.now(tz=timezone.utc) - timedelta(minutes=lookback_minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
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
