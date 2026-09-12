"""
WebSocket router.

Endpoint:
    WS /api/v1/ws/alerts?token=<access_token>

Auth:
    Browsers cannot set arbitrary headers during the WebSocket handshake,
    so the JWT access token is passed as a query parameter instead of an
    Authorization header. The token is validated with the same
    decode_token() used by the REST auth dependency — a WS connection
    with an invalid/expired token is rejected with close code 4401
    before being added to the connection manager.

Reconnects:
    The client is expected to reconnect (with backoff) on any drop. On
    reconnect, the client should also call GET /api/v1/alerts/recent to
    catch up on anything published while it was offline — this endpoint
    only streams events that occur while connected, it does not replay
    history.
"""

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.security import TokenError, decode_token
from app.services.websocket_manager import manager

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["websocket"])

WS_POLICY_VIOLATION = 4401


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket, token: str = Query(...)) -> None:
    try:
        decode_token(token, expected_type="access")
    except TokenError:
        await websocket.close(code=WS_POLICY_VIOLATION, reason="Invalid or expired token")
        return

    await manager.connect(websocket)
    try:
        while True:
            # Clients don't need to send anything; this just keeps the
            # connection loop alive and detects disconnects promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
