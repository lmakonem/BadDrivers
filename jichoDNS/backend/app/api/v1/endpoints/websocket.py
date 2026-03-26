"""
WebSocket endpoint for real-time IOC streaming.

Clients connect to receive new IOCs as they are imported from threat feeds.
Uses Redis pub/sub to receive notifications from Celery workers.
"""

import asyncio
import json
import logging
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query as QueryParam
from redis.asyncio import Redis

from app.core.config import settings
from app.core.security import decode_token

router = APIRouter()
logger = logging.getLogger(__name__)

# Store active WebSocket connections
active_connections: Set[WebSocket] = set()

# Redis channel for IOC broadcasts
IOC_CHANNEL = "jichodns:iocs:new"


class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket):
        """Accept and track a new connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a connection."""
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        if not self.active_connections:
            return
        
        data = json.dumps(message)
        disconnected = set()
        
        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(data)
                except Exception as e:
                    logger.warning(f"Failed to send to client: {e}")
                    disconnected.add(connection)
        
        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                self.active_connections -= disconnected


manager = ConnectionManager()


async def redis_subscriber():
    """
    Subscribe to Redis channel and broadcast new IOCs to WebSocket clients.
    
    This runs as a background task when the first client connects.
    """
    redis_url = settings.REDIS_URL
    if not redis_url:
        logger.error("REDIS_URL not configured")
        return
    
    try:
        redis = Redis.from_url(redis_url)
        pubsub = redis.pubsub()
        await pubsub.subscribe(IOC_CHANNEL)
        
        logger.info(f"Subscribed to Redis channel: {IOC_CHANNEL}")
        
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    # Support both "indicators" and "data" field names from worker
                    iocs = data.get("data") or data.get("indicators", [])
                    await manager.broadcast({
                        "type": "new_iocs",
                        "data": iocs,           # frontend expects "data"
                        "indicators": iocs,     # legacy compat
                        "source": data.get("source", "unknown"),
                        "count": data.get("count", len(iocs)),
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Redis message: {e}")
    except Exception as e:
        logger.error(f"Redis subscriber error: {e}")
    finally:
        await pubsub.close()
        await redis.close()


# Background task for Redis subscription
_subscriber_task = None


async def ensure_subscriber_running():
    """Start the Redis subscriber if not already running."""
    global _subscriber_task
    
    if _subscriber_task is None or _subscriber_task.done():
        _subscriber_task = asyncio.create_task(redis_subscriber())
        logger.info("Started Redis subscriber task")


@router.websocket("/ws/iocs")
async def websocket_iocs(
    websocket: WebSocket,
    token: str = QueryParam(default=""),
):
    """
    WebSocket endpoint for real-time IOC streaming.
    
    Accepts an optional JWT token as query parameter: /ws/iocs?token=<jwt>
    Public access allowed so the landing-page threat map works for everyone.
    
    Clients receive:
    - {"type": "connected", "message": "Connected to JichoDNS IOC stream"}
    - {"type": "new_iocs", "indicators": [...], "source": "urlhaus", "count": 10}
    - {"type": "ping"} every 30 seconds
    
    Clients can send:
    - {"type": "pong"} in response to ping
    """
    await manager.connect(websocket)
    
    # Ensure Redis subscriber is running
    await ensure_subscriber_running()
    
    # Send welcome message
    await websocket.send_json({
        "type": "connected",
        "message": "Connected to JichoDNS IOC stream",
        "total_connections": len(manager.active_connections),
    })
    
    try:
        # Keep connection alive with pings
        while True:
            try:
                # Wait for client messages with timeout for ping
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle client messages
                try:
                    message = json.loads(data)
                    if message.get("type") == "pong":
                        pass  # Keepalive response
                except json.JSONDecodeError:
                    pass
                    
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
                    
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


# Export manager for use by other modules
def get_connection_manager() -> ConnectionManager:
    """Get the WebSocket connection manager."""
    return manager
