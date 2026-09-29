import platform
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.config import settings
from app.core.database import get_db
from app.collectors.registry import list_supported_operations, COLLECTOR_REGISTRY

router = APIRouter(tags=["Health"])

@router.get("/health")
def get_health(db: Session = Depends(get_db)):
    """Health check endpoint validating API, DB, and system environment."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version()
        },
        "database": db_status,
        "demo_mode": settings.DEMO_MODE,
        "max_rounds": settings.MAX_ROUNDS
    }


@router.get("/capabilities")
@router.get("/health/capabilities")
def get_capabilities():
    """
    Platform capability matrix: reports which forensic collectors are available
    on the current OS. Collectors unavailable due to OS/permission constraints
    will have 'available: false' with a reason.
    """
    import psutil
    sys = platform.system()
    is_windows = sys == "Windows"
    is_linux = sys == "Linux"

    def _probe(op: str) -> dict:
        """Fast capability check validating collector registration and platform support."""
        collector = COLLECTOR_REGISTRY.get(op)
        if not collector:
            return {"available": False, "reason": "Collector not registered"}
        return {
            "available": True,
            "name": getattr(collector, "name", op),
            "operation": op,
            "description": getattr(collector, "description", "")
        }

    collectors: dict = {}

    # Fast probes (always safe)
    collectors["SYSTEM.INFO"]          = _probe("SYSTEM.INFO")
    collectors["PROCESS.LIST"]         = _probe("PROCESS.LIST")
    collectors["NETWORK.CONNECTIONS"]  = _probe("NETWORK.CONNECTIONS")
    collectors["DNS.INFO"]             = _probe("DNS.INFO")
    collectors["USERS.LIST"]           = _probe("USERS.LIST")
    collectors["FILES.RECENT"]         = _probe("FILES.RECENT")
    collectors["FILE.HASH"]            = {"available": True, "note": "SHA-256 on demand"}
    collectors["PROCESS.PARENT_CHILD"] = _probe("PROCESS.PARENT_CHILD")
    collectors["COMMANDLINE.INFO"]     = _probe("COMMANDLINE.INFO")

    # EVENTLOG: Windows-only full support
    if is_windows:
        collectors["EVENTLOG.RECENT"] = _probe("EVENTLOG.RECENT")
    elif is_linux:
        collectors["EVENTLOG.RECENT"] = {"available": True, "note": "journalctl/syslog"}
    else:
        collectors["EVENTLOG.RECENT"] = {"available": False, "reason": "Unsupported platform"}

    # DRIVERS: Windows full, Linux /proc/modules
    collectors["DRIVERS.LIST"] = _probe("DRIVERS.LIST")

    # MEMORY: Windows VirtualQueryEx, limited on Linux
    if is_windows:
        collectors["MEMORY.ANALYSIS"] = {"available": True, "note": "VirtualQueryEx via ctypes"}
    else:
        collectors["MEMORY.ANALYSIS"] = {"available": False, "reason": "Requires Windows VirtualQueryEx"}

    available_count = sum(1 for v in collectors.values() if v.get("available", False))

    return {
        "platform": sys,
        "architecture": platform.machine(),
        "total_collectors": len(collectors),
        "available_collectors": available_count,
        "collectors": collectors,
        "supported_operations": list_supported_operations(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
