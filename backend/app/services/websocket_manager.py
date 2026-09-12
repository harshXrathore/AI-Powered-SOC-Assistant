"""
WebSocket connection manager.

Purpose:
    Tracks connected WebSocket clients and broadcasts new-alert events to
    all of them. Kept as a plain in-process singleton for Phase 2 — the
    Celery worker runs in a separate process from the FastAPI app, so it
    cannot call this manager's `broadcast()` directly. Instead the sync
    task publishes to a Redis pub/sub channel, and a background listener
    inside the FastAPI process forwards those messages to connected
    WebSocket clients. See app/api/routers/websocket.py for the listener.

Reconnect handling:
    Clients are expected to reconnect on drop (standard exponential
    backoff on the frontend). The manager itself is stateless per
    connection — there is no message replay/buffering for a client that
    was briefly disconnected; on reconnect the client just resumes
    receiving new alerts from that point forward. A "catch-up via REST"
    pattern (call GET /alerts/recent after reconnecting) covers any gap.
"""

import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections.add(websocket)
        logger.info("websocket_connected", total_connections=len(self._active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self._active_connections.discard(websocket)
        logger.info("websocket_disconnected", total_connections=len(self._active_connections))

    async def broadcast_json(self, message: dict) -> None:
        """
        Sends `message` to every connected client. Dead connections
        (client closed without a clean disconnect) are pruned rather than
        allowed to raise on every subsequent broadcast.
        """
        dead_connections = []
        for connection in self._active_connections:
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001 — connection is dead, prune it
                dead_connections.append(connection)

        for connection in dead_connections:
            self.disconnect(connection)


manager = ConnectionManager()
