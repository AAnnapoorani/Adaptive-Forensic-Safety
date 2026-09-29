from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.machine import Machine

router = APIRouter(prefix="/machines", tags=["Machines"])

@router.get("")
def list_machines(db: Session = Depends(get_db)):
    """List all registered forensic machines."""
    machines = db.query(Machine).all()
    return [
        {
            "id": m.id,
            "hostname": m.hostname,
            "os_name": m.os_name,
            "os_version": m.os_version,
            "architecture": m.architecture,
            "ip_address": m.ip_address,
            "status": m.status,
            "last_seen": m.last_seen.isoformat() if m.last_seen else None,
            "created_at": m.created_at.isoformat() if m.created_at else None
        }
        for m in machines
    ]

@router.get("/{machine_id}")
def get_machine(machine_id: str, db: Session = Depends(get_db)):
    """Get machine telemetry and details."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    return {
        "id": machine.id,
        "hostname": machine.hostname,
        "os_name": machine.os_name,
        "os_version": machine.os_version,
        "architecture": machine.architecture,
        "ip_address": machine.ip_address,
        "status": machine.status,
        "last_seen": machine.last_seen.isoformat() if machine.last_seen else None,
        "created_at": machine.created_at.isoformat() if machine.created_at else None
    }
