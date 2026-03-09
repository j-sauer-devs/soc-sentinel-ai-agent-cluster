"""WebSocket endpoint for real-time alert streaming."""

from __future__ import annotations

import asyncio
import json
import logging
import random

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.mock_data import generate_alert
from server.routes_alerts import get_alerts_store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ws-alerts"])


@router.websocket("/ws/alerts")
async def alert_stream(ws: WebSocket):
    """Push new mock alerts to connected clients every 3-8 seconds."""
    await ws.accept()
    logger.info("WebSocket /ws/alerts: client connected")
    alerts_store = get_alerts_store()

    try:
        while True:
            delay = random.uniform(3.0, 8.0)
            await asyncio.sleep(delay)

            alert = generate_alert()
            alerts_store.insert(0, alert)

            # Keep the store from growing unbounded
            if len(alerts_store) > 200:
                alerts_store.pop()

            await ws.send_text(json.dumps({
                "type": "new_alert",
                "data": alert.model_dump(mode="json"),
            }, default=str))
    except WebSocketDisconnect:
        logger.info("WebSocket /ws/alerts: client disconnected")
    except Exception as e:
        logger.error("WebSocket /ws/alerts error: %s", e)
        try:
            await ws.close()
        except Exception:
            pass
