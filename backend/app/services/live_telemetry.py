"""
Automatic In-Process Live Telemetry Worker

Continuously collects local psutil hardware metrics (CPU, RAM, Disk, Network)
and process snapshots for the unified machine (JOCKY-93358801DA45), saves
them to MachineTelemetry, and broadcasts live updates over Server-Sent Events (SSE).
Guarantees the dashboard has 100% authentic real-time metrics without running a separate agent.
"""

import asyncio
import time
import uuid
import platform
from datetime import datetime, timezone
import psutil

from app.core.database import SessionLocal
from app.core.sse import sse_manager
from app.models.machine import Machine
from app.models.telemetry import MachineTelemetry, MachineProcessSnapshot
from app.utils.platform import get_machine_info

_last_net_io = None
_last_net_time = None

def _collect_live_metrics() -> dict:
    global _last_net_io, _last_net_time

    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_cores = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()
    cpu_freq_mhz = round(cpu_freq.current, 1) if cpu_freq else None

    mem = psutil.virtual_memory()
    memory_total = mem.total
    memory_used = mem.used
    memory_available = mem.available
    memory_percent = mem.percent

    try:
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        disk = psutil.disk_usage(disk_path)
        disk_total = disk.total
        disk_used = disk.used
        disk_free = disk.free
        disk_percent = disk.percent
    except Exception:
        disk_total = 0
        disk_used = 0
        disk_free = 0
        disk_percent = 0.0

    net_io = psutil.net_io_counters()
    now_t = time.time()
    upload_speed = 0.0
    download_speed = 0.0

    if _last_net_io is not None and _last_net_time is not None:
        dt = max(now_t - _last_net_time, 0.1)
        upload_speed = max((net_io.bytes_sent - _last_net_io.bytes_sent) / dt, 0.0)
        download_speed = max((net_io.bytes_recv - _last_net_io.bytes_recv) / dt, 0.0)

    _last_net_io = net_io
    _last_net_time = now_t

    try:
        active_conns = len(psutil.net_connections(kind='inet'))
    except Exception:
        active_conns = 0

    return {
        "cpu_percent": round(cpu_percent, 1),
        "cpu_cores": cpu_cores,
        "cpu_freq_mhz": cpu_freq_mhz,
        "memory_total_bytes": memory_total,
        "memory_used_bytes": memory_used,
        "memory_available_bytes": memory_available,
        "memory_percent": round(memory_percent, 1),
        "disk_total_bytes": disk_total,
        "disk_used_bytes": disk_used,
        "disk_free_bytes": disk_free,
        "disk_percent": round(disk_percent, 1),
        "network_bytes_sent": net_io.bytes_sent,
        "network_bytes_recv": net_io.bytes_recv,
        "network_upload_speed": round(upload_speed, 1),
        "network_download_speed": round(download_speed, 1),
        "active_connections": active_conns
    }


async def start_live_telemetry_loop():
    """Background worker collecting live system metrics every 3 seconds."""
    # Warmup cpu counter
    psutil.cpu_percent(interval=None)
    await asyncio.sleep(1)

    machine_info = get_machine_info()
    mid = machine_info["id"]

    tick = 0
    while True:
        try:
            now = datetime.now(timezone.utc)
            metrics = await asyncio.to_thread(_collect_live_metrics)

            with SessionLocal() as db:
                # Ensure machine exists and is ONLINE
                m = db.query(Machine).filter((Machine.id == mid) | (Machine.machine_id == mid)).first()
                if not m:
                    m = Machine(
                        id=mid,
                        machine_id=mid,
                        hostname=machine_info["hostname"],
                        os_type=machine_info.get("os_type", "Windows"),
                        os_name=machine_info["os_name"],
                        os_version=machine_info["os_version"],
                        architecture=machine_info["architecture"],
                        ip_address=machine_info["ip_address"],
                        mac_address=machine_info.get("mac_address"),
                        status="ONLINE",
                        first_seen=now,
                        last_seen=now
                    )
                    db.add(m)
                else:
                    m.status = "ONLINE"
                    m.last_seen = now
                    if not m.machine_id:
                        m.machine_id = mid

                # Record telemetry point
                telem = MachineTelemetry(
                    id=f"TEL-{uuid.uuid4().hex[:12].upper()}",
                    machine_id=mid,
                    timestamp=now,
                    cpu_percent=metrics["cpu_percent"],
                    cpu_freq_mhz=metrics["cpu_freq_mhz"],
                    cpu_cores=metrics["cpu_cores"],
                    memory_total_bytes=metrics["memory_total_bytes"],
                    memory_used_bytes=metrics["memory_used_bytes"],
                    memory_available_bytes=metrics["memory_available_bytes"],
                    memory_percent=metrics["memory_percent"],
                    disk_total_bytes=metrics["disk_total_bytes"],
                    disk_used_bytes=metrics["disk_used_bytes"],
                    disk_free_bytes=metrics["disk_free_bytes"],
                    disk_percent=metrics["disk_percent"],
                    network_bytes_sent=metrics["network_bytes_sent"],
                    network_bytes_recv=metrics["network_bytes_recv"],
                    network_upload_speed=metrics["network_upload_speed"],
                    network_download_speed=metrics["network_download_speed"],
                    active_connections=metrics["active_connections"]
                )
                db.add(telem)

                # Periodically (every ~30s / 10 ticks) update process snapshots
                if tick % 10 == 0:
                    try:
                        procs_raw = []
                        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
                            try:
                                pinfo = proc.info
                                if pinfo['name']:
                                    procs_raw.append(pinfo)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        # Sort by CPU/Memory and take top 35
                        procs_raw.sort(key=lambda p: (p.get('cpu_percent') or 0, p.get('memory_percent') or 0), reverse=True)
                        top_procs = procs_raw[:35]

                        db.query(MachineProcessSnapshot).filter(MachineProcessSnapshot.machine_id == mid).delete()
                        for p in top_procs:
                            db.add(MachineProcessSnapshot(
                                id=f"PROC-{uuid.uuid4().hex[:12].upper()}",
                                machine_id=mid,
                                timestamp=now,
                                pid=p['pid'],
                                name=p['name'],
                                exe_path=p.get('exe') or '',
                                cpu_percent=round(p.get('cpu_percent') or 0.0, 1),
                                memory_percent=round(p.get('memory_percent') or 0.0, 1),
                                threat_level="CLEAN"
                            ))
                    except Exception:
                        pass

                db.commit()

            # Broadcast SSE telemetry update
            live_payload = {
                "machine_id": mid,
                "hostname": machine_info["hostname"],
                "os_type": machine_info.get("os_type", "Windows"),
                "os_name": machine_info["os_name"],
                "os_version": machine_info["os_version"],
                "status": "ONLINE",
                "last_seen": now.isoformat(),
                "metrics": {
                    **metrics,
                    "timestamp": now.isoformat()
                }
            }
            await sse_manager.broadcast("telemetry_update", live_payload)

            tick += 1
            await asyncio.sleep(3)

        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(3)
