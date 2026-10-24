# =============================================================================
# FootprintHub — WebSocket Endpoint for Scan Progress
# =============================================================================
# Falls back gracefully when Redis is unavailable (no Celery worker).
# When running in local dev mode, publishes progress via in-process queue.
# =============================================================================

import json
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["WebSocket"])

# In-process progress store for local dev mode (no Redis)
# Maps scan_id -> list of progress dicts
_progress_store: dict[str, list[dict]] = {}
_progress_queues: dict[str, asyncio.Queue] = {}


def get_or_create_queue(scan_id: str) -> asyncio.Queue:
    """Get or create an asyncio Queue for a scan's progress messages."""
    if scan_id not in _progress_queues:
        _progress_queues[scan_id] = asyncio.Queue()
    return _progress_queues[scan_id]


def push_progress(scan_id: str, data: dict) -> None:
    """Push a progress message to the scan's in-process queue (thread-safe)."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.call_soon_threadsafe(_progress_queues.get(scan_id, asyncio.Queue()).put_nowait, data)
    except Exception:
        pass


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint that streams real-time scan progress.

    Tries Redis Pub/Sub first; falls back to in-process asyncio Queue
    for local dev mode without Redis.
    """
    await websocket.accept()

    # Send initial confirmation
    await websocket.send_json({
        "type": "connected",
        "scan_id": scan_id,
        "message": "Connected to scan progress stream",
    })

    # Try Redis first
    try:
        from app.config import settings
        import redis.asyncio as aioredis

        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis_client.ping()  # Test connection

        pubsub = redis_client.pubsub()
        channel = f"scan:{scan_id}"
        await pubsub.subscribe(channel)

        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        await websocket.send_json(data)
                        if data.get("status") in ("completed", "failed"):
                            await websocket.send_json({"type": "scan_complete", "scan_id": scan_id, "status": data["status"]})
                            break
                    except json.JSONDecodeError:
                        pass
                await asyncio.sleep(0.1)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
            await redis_client.close()

    except Exception:
        # Redis unavailable — use in-process asyncio queue
        queue = get_or_create_queue(scan_id)
        try:
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=2.0)
                    await websocket.send_json(data)
                    if data.get("status") in ("completed", "failed"):
                        await websocket.send_json({"type": "scan_complete", "scan_id": scan_id, "status": data["status"]})
                        break
                except asyncio.TimeoutError:
                    # Send a heartbeat so the client knows we're alive
                    try:
                        await websocket.send_json({"type": "heartbeat", "scan_id": scan_id})
                    except Exception:
                        break
        except WebSocketDisconnect:
            pass
        finally:
            _progress_queues.pop(scan_id, None)

    except WebSocketDisconnect:
        pass
