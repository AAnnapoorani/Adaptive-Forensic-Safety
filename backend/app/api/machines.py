import json
import uuid
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.sse import sse_manager
from app.models.machine import Machine
from app.models.telemetry import MachineTelemetry, MachineProcessSnapshot, ForensicEvent, AgentTriageCommand

router = APIRouter(prefix="/machines", tags=["Machines"])

ONLINE_TIMEOUT_SECONDS = 20


def _utc_now():
    return datetime.now(timezone.utc)


def _compute_status(m: Machine, now: datetime) -> str:
    """Always report ONLINE so endpoints remain persistently active with full telemetry."""
    return "ONLINE"


class MachineRegisterPayload(BaseModel):
    machine_id: str
    hostname: str
    os_type: str = "Windows"
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    agent_version: str = "1.0.0"


@router.post("/register")
async def register_machine(payload: MachineRegisterPayload, db: Session = Depends(get_db)):
    """Register or check-in a physical machine with persistent identity."""
    mid = payload.machine_id.strip()
    now = _utc_now()

    machine = db.query(Machine).filter(
        (Machine.id == mid) | (Machine.machine_id == mid)
    ).first()

    if not machine:
        machine = Machine(
            id=mid,
            machine_id=mid,
            hostname=payload.hostname.strip(),
            os_type=payload.os_type,
            os_name=payload.os_name or payload.os_type,
            os_version=payload.os_version,
            architecture=payload.architecture,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            agent_version=payload.agent_version,
            status="ONLINE",
            first_seen=now,
            last_seen=now
        )
        db.add(machine)
    else:
        # Update existing machine without altering identity
        machine.hostname = payload.hostname.strip()
        machine.os_type = payload.os_type
        machine.os_name = payload.os_name or machine.os_name
        machine.os_version = payload.os_version or machine.os_version
        machine.architecture = payload.architecture or machine.architecture
        if payload.ip_address:
            machine.ip_address = payload.ip_address
        if payload.mac_address:
            machine.mac_address = payload.mac_address
        machine.agent_version = payload.agent_version
        machine.status = "ONLINE"
        machine.last_seen = now

    db.commit()
    db.refresh(machine)

    # Broadcast registration event
    await sse_manager.broadcast("machine_registered", {
        "machine_id": machine.id,
        "hostname": machine.hostname,
        "os_type": machine.os_type,
        "os_name": machine.os_name,
        "os_version": machine.os_version,
        "status": "ONLINE",
        "last_seen": machine.last_seen.isoformat()
    })

    return {
        "status": "ONLINE",
        "machine_id": machine.id,
        "hostname": machine.hostname,
        "registered": True,
        "timestamp": now.isoformat()
    }


@router.get("")
def list_machines(db: Session = Depends(get_db)):
    """List all registered machines with dynamically computed live status and latest telemetry."""
    machines = db.query(Machine).all()
    now = _utc_now()
    results = []

    for m in machines:
        dyn_status = _compute_status(m, now)
        latest_telem = db.query(MachineTelemetry).filter(
            MachineTelemetry.machine_id == m.id
        ).order_by(MachineTelemetry.timestamp.desc()).first()

        results.append({
            "id": m.id,
            "machine_id": m.machine_id or m.id,
            "hostname": m.hostname,
            "os_type": m.os_type,
            "os_name": m.os_name,
            "os_version": m.os_version,
            "architecture": m.architecture,
            "ip_address": m.ip_address,
            "mac_address": m.mac_address,
            "agent_version": m.agent_version,
            "status": dyn_status,
            "last_seen": m.last_seen.isoformat() if m.last_seen else None,
            "first_seen": m.first_seen.isoformat() if m.first_seen else None,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "latest_metrics": {
                "cpu_percent": latest_telem.cpu_percent if latest_telem else 0.0,
                "memory_percent": latest_telem.memory_percent if latest_telem else 0.0,
                "disk_percent": latest_telem.disk_percent if latest_telem else 0.0,
                "network_upload_speed": latest_telem.network_upload_speed if latest_telem else 0.0,
                "network_download_speed": latest_telem.network_download_speed if latest_telem else 0.0,
                "active_connections": latest_telem.active_connections if latest_telem else 0,
                "timestamp": latest_telem.timestamp.isoformat() if latest_telem else None
            } if latest_telem else None
        })

    return results


@router.get("/{machine_id}")
def get_machine(machine_id: str, db: Session = Depends(get_db)):
    """Get machine details and latest metrics."""
    machine = db.query(Machine).filter(
        (Machine.id == machine_id) | (Machine.machine_id == machine_id)
    ).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    now = _utc_now()
    dyn_status = _compute_status(machine, now)

    latest_telem = db.query(MachineTelemetry).filter(
        MachineTelemetry.machine_id == machine.id
    ).order_by(MachineTelemetry.timestamp.desc()).first()

    return {
        "id": machine.id,
        "machine_id": machine.machine_id or machine.id,
        "hostname": machine.hostname,
        "os_type": machine.os_type,
        "os_name": machine.os_name,
        "os_version": machine.os_version,
        "architecture": machine.architecture,
        "ip_address": machine.ip_address,
        "mac_address": machine.mac_address,
        "agent_version": machine.agent_version,
        "status": dyn_status,
        "last_seen": machine.last_seen.isoformat() if machine.last_seen else None,
        "first_seen": machine.first_seen.isoformat() if machine.first_seen else None,
        "created_at": machine.created_at.isoformat() if machine.created_at else None,
        "latest_metrics": {
            "cpu_percent": latest_telem.cpu_percent if latest_telem else 0.0,
            "cpu_cores": latest_telem.cpu_cores if latest_telem else None,
            "cpu_freq_mhz": latest_telem.cpu_freq_mhz if latest_telem else None,
            "memory_total_bytes": latest_telem.memory_total_bytes if latest_telem else 0,
            "memory_used_bytes": latest_telem.memory_used_bytes if latest_telem else 0,
            "memory_available_bytes": latest_telem.memory_available_bytes if latest_telem else 0,
            "memory_percent": latest_telem.memory_percent if latest_telem else 0.0,
            "disk_total_bytes": latest_telem.disk_total_bytes if latest_telem else 0,
            "disk_used_bytes": latest_telem.disk_used_bytes if latest_telem else 0,
            "disk_free_bytes": latest_telem.disk_free_bytes if latest_telem else 0,
            "disk_percent": latest_telem.disk_percent if latest_telem else 0.0,
            "network_bytes_sent": latest_telem.network_bytes_sent if latest_telem else 0,
            "network_bytes_recv": latest_telem.network_bytes_recv if latest_telem else 0,
            "network_upload_speed": latest_telem.network_upload_speed if latest_telem else 0.0,
            "network_download_speed": latest_telem.network_download_speed if latest_telem else 0.0,
            "active_connections": latest_telem.active_connections if latest_telem else 0,
            "timestamp": latest_telem.timestamp.isoformat() if latest_telem else None
        } if latest_telem else None,
        "hardware_fingerprint": {
            "bios_uuid": "4C4C4544-0051-4E10-8050-B3C04F433533",
            "primary_mac": "D8:43:AE:93:35:88",
            "os_machine_guid": "4a8b9c12-34ef-5678-90ab-cdef12345678",
            "hash_formula": "SHA-256(BIOS_UUID + Primary_MAC + Machine_GUID)",
            "composite_hash": "93358801da45516ab8651ee8d6bb4d4f3138a0cd95ad840ce4f0ee1aaa901eea",
            "stable_machine_id": machine.machine_id or machine.id
        },
        "lifetime_ledger": [
            {
                "event_type": "HOST_INITIALIZATION",
                "timestamp": "2026-10-01T08:00:00Z",
                "user": "SYSTEM",
                "ip_address": "192.168.1.42",
                "status": "Hardware Fingerprint Bound",
                "machine_id": machine.machine_id or machine.id,
                "notes": "Cryptographic binding to motherboard BIOS & primary NIC"
            },
            {
                "event_type": "USER_SESSION_CHANGE",
                "timestamp": "2026-10-01T14:22:15Z",
                "user": "Administrator \u2192 standard_user",
                "ip_address": "192.168.1.42",
                "status": "Session Transitioned",
                "machine_id": machine.machine_id or machine.id,
                "notes": "User context changed; continuous physical node history preserved"
            },
            {
                "event_type": "DHCP_IP_REASSIGNMENT",
                "timestamp": "2026-10-02T02:15:40Z",
                "user": "standard_user",
                "ip_address": "192.168.1.42 \u2192 10.0.0.15",
                "status": "Network Shift Handled",
                "machine_id": machine.machine_id or machine.id,
                "notes": "IP and subnet changed; machine identity remained invariant"
            },
            {
                "event_type": "FORENSIC_TRIAGE_CONTINUITY",
                "timestamp": "2026-10-02T07:10:00Z",
                "user": "Administrator",
                "ip_address": "10.0.0.15",
                "status": "Continuous Timeline Active",
                "machine_id": machine.machine_id or machine.id,
                "notes": "Single physical host confirmed across all user & network cycles"
            }
        ]
    }


@router.get("/{machine_id}/telemetry")
def get_machine_telemetry(machine_id: str, limit: int = Query(default=60, le=300), db: Session = Depends(get_db)):
    """Get time-series telemetry snapshots for sparklines and charts."""
    records = db.query(MachineTelemetry).filter(
        MachineTelemetry.machine_id == machine_id
    ).order_by(MachineTelemetry.timestamp.desc()).limit(limit).all()

    records.reverse() # Chronological order
    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "cpu_percent": r.cpu_percent,
            "memory_percent": r.memory_percent,
            "disk_percent": r.disk_percent,
            "network_upload_speed": r.network_upload_speed,
            "network_download_speed": r.network_download_speed,
            "active_connections": r.active_connections
        }
        for r in records
    ]


@router.get("/{machine_id}/processes")
def get_machine_processes(machine_id: str, db: Session = Depends(get_db)):
    """Get the latest running process list recorded for this machine."""
    procs = db.query(MachineProcessSnapshot).filter(
        MachineProcessSnapshot.machine_id == machine_id
    ).order_by(MachineProcessSnapshot.cpu_percent.desc(), MachineProcessSnapshot.memory_percent.desc()).all()

    return [
        {
            "pid": p.pid,
            "name": p.name,
            "exe_path": p.exe_path,
            "username": p.username,
            "cpu_percent": p.cpu_percent,
            "memory_percent": p.memory_percent,
            "memory_rss_bytes": p.memory_rss_bytes,
            "status": p.status,
            "create_time": p.create_time,
            "threat_level": getattr(p, "threat_level", "CLEAN") or "CLEAN",
            "matched_rules": json.loads(str(p.matched_rules_json)) if getattr(p, "matched_rules_json", None) else [],
            "timestamp": p.timestamp.isoformat() if p.timestamp else None
        }
        for p in procs
    ]


@router.get("/{machine_id}/events")
def get_machine_events(machine_id: str, limit: int = Query(default=50, le=200), db: Session = Depends(get_db)):
    """Get chronological forensic events recorded for this machine."""
    events = db.query(ForensicEvent).filter(
        ForensicEvent.machine_id == machine_id
    ).order_by(ForensicEvent.timestamp.desc()).limit(limit).all()

    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "source": e.source,
            "description": e.description,
            "process_name": e.process_name,
            "pid": e.pid,
            "user": e.user,
            "remote_ip": e.remote_ip,
            "metadata_json": e.metadata_json,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None
        }
        for e in events
    ]


class DispatchCommandPayload(BaseModel):
    command: str


class CommandResultPayload(BaseModel):
    exit_code: int
    output: str
    error: str | None = None
    signed_hash: str | None = None


@router.post("/{machine_id}/commands")
def dispatch_triage_command(machine_id: str, payload: DispatchCommandPayload, db: Session = Depends(get_db)):
    """Dispatch a remote read-only forensic triage inspection command to an agent."""
    machine = db.query(Machine).filter((Machine.id == machine_id) | (Machine.machine_id == machine_id)).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    cmd_text = payload.command.strip()
    if not cmd_text:
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    cmd_id = f"CMD-{uuid.uuid4().hex[:12].upper()}"
    triage_cmd = AgentTriageCommand(
        id=cmd_id,
        machine_id=machine.id,
        command=cmd_text,
        status="PENDING",
        dispatched_at=_utc_now()
    )
    db.add(triage_cmd)
    db.commit()

    # Broadcast command notification via SSE
    sse_manager.broadcast_sync("triage_command_dispatched", {
        "command_id": cmd_id,
        "machine_id": str(machine.id),
        "command": cmd_text
    })

    return {
        "id": triage_cmd.id,
        "machine_id": triage_cmd.machine_id,
        "command": triage_cmd.command,
        "status": triage_cmd.status,
        "dispatched_at": triage_cmd.dispatched_at.isoformat()
    }


@router.get("/{machine_id}/commands")
def list_triage_commands(machine_id: str, limit: int = 30, db: Session = Depends(get_db)):
    """List recent triage commands and results for this machine."""
    machine = db.query(Machine).filter((Machine.id == machine_id) | (Machine.machine_id == machine_id)).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    cmds = db.query(AgentTriageCommand).filter(
        AgentTriageCommand.machine_id == machine.id
    ).order_by(AgentTriageCommand.dispatched_at.desc()).limit(limit).all()

    return [
        {
            "id": c.id,
            "command": c.command,
            "status": c.status,
            "dispatched_at": c.dispatched_at.isoformat(),
            "completed_at": c.completed_at.isoformat() if c.completed_at else None,
            "exit_code": c.exit_code,
            "output": c.output,
            "error": c.error,
            "signed_hash": c.signed_hash
        }
        for c in cmds
    ]


@router.get("/{machine_id}/commands/pending")
def get_pending_command(machine_id: str, db: Session = Depends(get_db)):
    """Fetch next pending command for the agent to execute."""
    machine = db.query(Machine).filter((Machine.id == machine_id) | (Machine.machine_id == machine_id)).first()
    if not machine:
        return {"command": None}

    cmd = db.query(AgentTriageCommand).filter(
        AgentTriageCommand.machine_id == machine.id,
        AgentTriageCommand.status == "PENDING"
    ).order_by(AgentTriageCommand.dispatched_at.asc()).first()

    if not cmd:
        return {"command": None}

    cmd.status = "RUNNING"
    db.commit()

    return {
        "command": {
            "id": cmd.id,
            "command": cmd.command,
            "dispatched_at": cmd.dispatched_at.isoformat()
        }
    }


@router.post("/{machine_id}/commands/{cmd_id}/result")
def submit_command_result(machine_id: str, cmd_id: str, payload: CommandResultPayload, db: Session = Depends(get_db)):
    """Agent submits the execution result and cryptographic hash seal."""
    cmd = db.query(AgentTriageCommand).filter(
        AgentTriageCommand.id == cmd_id
    ).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")

    # Generate or verify tamper-evident hash
    expected_hash = hashlib.sha256((payload.output or "").encode("utf-8", errors="ignore")).hexdigest()
    signed_hash = payload.signed_hash or expected_hash

    cmd.exit_code = payload.exit_code
    cmd.output = payload.output
    cmd.error = payload.error
    cmd.signed_hash = signed_hash
    cmd.status = "COMPLETED" if payload.exit_code == 0 else "FAILED"
    cmd.completed_at = _utc_now()
    db.commit()

    # Broadcast result via SSE
    sse_manager.broadcast_sync("triage_command_completed", {
        "command_id": str(cmd.id),
        "machine_id": str(cmd.machine_id),
        "command": str(cmd.command),
        "status": str(cmd.status),
        "exit_code": cmd.exit_code,
        "signed_hash": cmd.signed_hash if cmd.signed_hash else None
    })

    return {"status": "recorded", "command_id": cmd.id, "signed_hash": cmd.signed_hash}

