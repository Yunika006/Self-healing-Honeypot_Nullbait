import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from services.event_bus import event_bus
from core.metrics import active_websocket_connections
from core.security import verify_token

log = logging.getLogger("nullbait.websocket")

router = APIRouter()


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str = Query(...)):
    try:
        verify_token(token)
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    queue = event_bus.subscribe()
    active_websocket_connections.inc()
    log.info("dashboard client connected via websocket")

    try:
        while True:
            message = await queue.get()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        log.info("dashboard client disconnected")
    finally:
        event_bus.unsubscribe(queue)
        active_websocket_connections.dec()
