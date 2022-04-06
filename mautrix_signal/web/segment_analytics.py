from __future__ import annotations

import asyncio
import logging

from yarl import URL
import aiohttp

from .. import user as u

log = logging.getLogger("mau.web.public.analytics")
segment_url: URL = URL("https://api.segment.io/v1/track")
http: aiohttp.ClientSession | None = None
segment_key: str | None = None


async def _track(user: u.User, event: str, properties: dict) -> None:
    await http.post(
        segment_url,
        json={
            "userId": user.mxid,
            "event": event,
            "properties": {"bridge": "signal", **properties},
        },
        auth=aiohttp.BasicAuth(login=segment_key, encoding="utf-8"),
    )
    log.debug(f"Tracked {event}")


def track(user: u.User, event: str, properties: dict | None = None):
    if segment_key:
        asyncio.create_task(_track(user, event, properties or {}))


def init(key):
    global segment_key, http
    segment_key = key
    http = aiohttp.ClientSession()
