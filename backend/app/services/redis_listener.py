"""
Redis pub/sub listener.

Purpose:
    The Celery worker runs in a separate process from FastAPI, so it
    can't call ConnectionManager.broadcast_json() directly — it publishes
    new-alert events to a Redis channel instead (see
    services/tasks/wazuh_tasks.py). This module runs a single background
    task, started at FastAPI startup, that subscribes to that channel and
    forwards every message to all currently-connected WebSocket clients.
"""

import asyncio
import json

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.services.tasks.wazuh_tasks import NEW_ALERT_CHANNEL
from app.services.websocket_manager import manager

logger = structlog.get_logger(__name__)

_listener_task: asyncio.Task | None = None


async def _listen() -> None:
    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(NEW_ALERT_CHANNEL)
    logger.info("redis_listener_started", channel=NEW_ALERT_CHANNEL)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                payload = json.loads(message["data"])
            except json.JSONDecodeError:
                logger.warning("redis_listener_bad_payload", raw=message["data"])
                continue
            await manager.broadcast_json(payload)
    except asyncio.CancelledError:
        logger.info("redis_listener_stopping")
        raise
    finally:
        await pubsub.unsubscribe(NEW_ALERT_CHANNEL)
        await pubsub.close()
        await redis_client.close()


def start_listener() -> None:
    global _listener_task
    if _listener_task is None or _listener_task.done():
        _listener_task = asyncio.create_task(_listen())


async def stop_listener() -> None:
    global _listener_task
    if _listener_task is not None:
        _listener_task.cancel()
        try:
            await _listener_task
        except asyncio.CancelledError:
            pass
        _listener_task = None
