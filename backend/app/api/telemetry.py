"""
JOCKY Live Telemetry Ingestion & Server-Sent Events (SSE) Stream Router

Endpoints:
  POST /api/telemetry               — Ingest live telemetry packets from physical agents
  GET  /api/stream                  — SSE stream broadcasting live telemetry & status
  GET  /api/telemetry/stats         — Global telemetry overview (total machines, online count, alerts)
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.sse import sse_manager
from app.models.machine import Machine
from app.models.telemetry import MachineTelemetry, MachineProcessSnapshot, ForensicEvent

router = APIRouter(prefix="", tags=["Live Telemetry & SSE Streaming"])


def _utc_now():
    return datetime.now(timezone.utc)


class SystemMetricsPayload(BaseModel):
    timestamp: str | None = None
    cpu_percent: float = 0.0
    cpu_freq_mhz: float | None = None
    cpu_cores: int | None = None
    memory_total_bytes: int = 0
    memory_used_bytes: int = 0
    memory_available_bytes: int = 0
    memory_percent: float = 0.0
    disk_total_bytes: int = 0
    disk_used_bytes: int = 0
    disk_free_bytes: int = 0
    disk_percent: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    network_upload_speed: float = 0.0
    network_download_speed: float = 0.0
    active_connections: int = 0


class TelemetryPacket(BaseModel):
    machine_id: str
    metrics: SystemMetricsPayload
    processes: list[dict] | None = None
    events: list[dict] | None = None


@router.post("/telemetry")
async def ingest_telemetry(packet: TelemetryPacket, db: Session = Depends(get_db)):
    """Ingest a live telemetry packet sent by a JOCKY local agent."""
    machine_id = packet.machine_id.strip()

    # Find or auto-register machine
    machine = db.query(Machine).filter(
        (Machine.id == machine_id) | (Machine.machine_id == machine_id)
    ).first()

    now = _utc_now()
    if not machine:
        machine = Machine(
            id=machine_id,
            machine_id=machine_id,
            hostname=f"host-{machine_id[-6:]}",
            os_type="Unknown",
            os_name="Unknown OS",
            status="ONLINE",
            first_seen=now,
            last_seen=now
        )
        db.add(machine)
    else:
        machine.status = "ONLINE"
        machine.last_seen = now

    # Store telemetry snapshot
    m = packet.metrics
    telem_record = MachineTelemetry(
        id=f"TEL-{uuid.uuid4().hex[:12].upper()}",
        machine_id=machine.id,
        timestamp=now,
        cpu_percent=m.cpu_percent,
        cpu_freq_mhz=m.cpu_freq_mhz,
        cpu_cores=m.cpu_cores,
        memory_total_bytes=m.memory_total_bytes,
        memory_used_bytes=m.memory_used_bytes,
        memory_available_bytes=m.memory_available_bytes,
        memory_percent=m.memory_percent,
        disk_total_bytes=m.disk_total_bytes,
        disk_used_bytes=m.disk_used_bytes,
        disk_free_bytes=m.disk_free_bytes,
        disk_percent=m.disk_percent,
        network_bytes_sent=m.network_bytes_sent,
        network_bytes_recv=m.network_bytes_recv,
        network_upload_speed=m.network_upload_speed,
        network_download_speed=m.network_download_speed,
        active_connections=m.active_connections
    )
    db.add(telem_record)

    # Ingest process snapshot if present (purge previous snapshot for clean state)
    if packet.processes:
        try:
            db.query(MachineProcessSnapshot).filter(
                MachineProcessSnapshot.machine_id == machine.id
            ).delete()

            for p in packet.processes[:40]:
                db.add(MachineProcessSnapshot(
                    id=f"PROC-{uuid.uuid4().hex[:12].upper()}",
                    machine_id=machine.id,
                    timestamp=now,
                    pid=p.get("pid", 0),
                    name=p.get("name", "unknown")[:128],
                    exe_path=p.get("exe_path"),
                    username=p.get("username", "SYSTEM")[:128],
                    cpu_percent=p.get("cpu_percent", 0.0),
                    memory_percent=p.get("memory_percent", 0.0),
                    memory_rss_bytes=p.get("memory_rss_bytes", 0),
                    status=p.get("status", "running"),
                    create_time=p.get("create_time"),
                    threat_level=p.get("threat_level", "CLEAN"),
                    matched_rules_json=json.dumps(p.get("matched_rules", [])) if p.get("matched_rules") else None
                ))
        except Exception:
            pass

    # Ingest forensic events if present
    broadcast_events = []
    if packet.events:
        for e in packet.events:
            evt_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
            evt = ForensicEvent(
                id=evt_id,
                machine_id=machine.id,
                timestamp=now,
                event_type=e.get("event_type", "SECURITY_ALERT"),
                severity=e.get("severity", "MEDIUM"),
                source=e.get("source", "Agent Monitor"),
                description=e.get("description", "Security event detected"),
                process_name=e.get("process_name"),
                pid=e.get("pid"),
                user=e.get("user"),
                remote_ip=e.get("remote_ip"),
                metadata_json=e.get("metadata_json")
            )
            db.add(evt)
            broadcast_events.append({
                "id": evt_id,
                "machine_id": machine.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "source": evt.source,
                "description": evt.description,
                "timestamp": now.isoformat()
            })

    db.commit()

    # Live SSE broadcast
    live_update = {
        "machine_id": machine.id,
        "hostname": machine.hostname,
        "os_type": machine.os_type,
        "os_name": machine.os_name,
        "os_version": machine.os_version,
        "status": "ONLINE",
        "last_seen": now.isoformat(),
        "metrics": {
            "cpu_percent": m.cpu_percent,
            "memory_percent": m.memory_percent,
            "disk_percent": m.disk_percent,
            "network_upload_speed": m.network_upload_speed,
            "network_download_speed": m.network_download_speed,
            "active_connections": m.active_connections
        }
    }
    await sse_manager.broadcast("telemetry_update", live_update)

    for bevt in broadcast_events:
        await sse_manager.broadcast("forensic_event", bevt)

    return {
        "status": "INGESTED",
        "machine_id": machine.id,
        "timestamp": now.isoformat()
    }


@router.get("/stream")
async def sse_stream(request: Request, db: Session = Depends(get_db)):
    """
    Server-Sent Events endpoint streaming real-time telemetry updates,
    machine status shifts, and forensic alerts to the React frontend.
    """
    q = sse_manager.register()

    # Prepare initial snapshot of active machines
    machines = db.query(Machine).all()
    now = _utc_now()
    initial_machines = []
    for m in machines:
        is_online = (m.last_seen and (now - m.last_seen.replace(tzinfo=timezone.utc if m.last_seen.tzinfo is None else m.last_seen.tzinfo)).total_seconds() <= 20)
        initial_machines.append({
            "id": m.id,
            "machine_id": m.machine_id or m.id,
            "hostname": m.hostname,
            "os_type": m.os_type,
            "os_name": m.os_name,
            "os_version": m.os_version,
            "status": "ONLINE" if is_online else "OFFLINE",
            "last_seen": m.last_seen.isoformat() if m.last_seen else None
        })

    async def event_generator():
        # Send initial connected greeting
        init_msg = json.dumps({
            "type": "INITIAL_STATE",
            "ts": now.isoformat(),
            "data": {"machines": initial_machines}
        })
        yield f"event: initial_state\ndata: {init_msg}\n\n"

        heartbeat_tick = 0
        try:
            while True:
                # Check for client disconnect
                if await request.is_disconnected():
                    break

                try:
                    # Wait up to 15 seconds for next broadcast event
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield msg
                except asyncio.TimeoutError:
                    # Send periodic SSE keepalive ping every 15s
                    heartbeat_tick += 1
                    yield f"event: ping\ndata: {{\"tick\": {heartbeat_tick}}}\n\n"

        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            sse_manager.unregister(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*"
        }
    )


@router.post("/telemetry/prune")
def trigger_telemetry_pruning(hours: int | None = None, db: Session = Depends(get_db)):
    """
    Manually trigger Free-Tier Guardian telemetry retention pruning.
    Prunes points older than `hours` (defaults to TELEMETRY_RETENTION_HOURS = 48).
    """
    from app.services.retention import prune_old_telemetry
    return prune_old_telemetry(db, hours=hours)

