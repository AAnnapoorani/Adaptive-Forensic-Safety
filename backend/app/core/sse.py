"""
JOCKY Server-Sent Events (SSE) Event Bus Manager

Provides fan-out event streaming for live telemetry, machine status changes,
and forensic alerts pushed directly to React frontend clients without polling.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Set


def _utc_iso():
    return datetime.now(timezone.utc).isoformat()


class SSEManager:
    def __init__(self):
        self._clients: Set[asyncio.Queue] = set()

    def register(self) -> asyncio.Queue:
        """Register a new frontend client queue."""
        q = asyncio.Queue(maxsize=100)
        self._clients.add(q)
        return q

    def unregister(self, q: asyncio.Queue):
        """Remove a disconnected client queue."""
        self._clients.discard(q)

    def broadcast_sync(self, event_type: str, data: dict):
        """Synchronously enqueue a structured event to all connected dashboard clients."""
        payload = {
            "type": event_type,
            "ts": _utc_iso(),
            "data": data
        }
        raw_msg = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

        disconnected = []
        for q in list(self._clients):
            try:
                if q.full():
                    # Evict oldest item to prevent memory buildup
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(raw_msg)
            except Exception:
                disconnected.append(q)

        for q in disconnected:
            self._clients.discard(q)

    async def broadcast(self, event_type: str, data: dict):
        """Broadcast a structured event to all connected dashboard clients."""
        self.broadcast_sync(event_type, data)


# Global singleton SSE manager
sse_manager = SSEManager()
