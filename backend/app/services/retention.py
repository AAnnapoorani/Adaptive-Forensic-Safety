"""
Free-Tier Retention Guardian Service

Automatically prunes high-frequency telemetry points and old process table snapshots
older than TELEMETRY_RETENTION_HOURS (default 48h) to guarantee that Supabase Postgres
storage never exceeds the 500 MB free-tier limit.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.core.config import settings
from app.models.telemetry import MachineTelemetry, MachineProcessSnapshot


def prune_old_telemetry(db: Session, hours: int | None = None) -> dict:
    """
    Delete telemetry records older than the cutoff threshold.
    Works seamlessly on both SQLite and PostgreSQL.
    """
    retention_hours = hours if hours is not None else settings.TELEMETRY_RETENTION_HOURS
    cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)

    try:
        # 1. Prune high-frequency telemetry points
        deleted_telemetry = db.query(MachineTelemetry).filter(
            MachineTelemetry.timestamp < cutoff
        ).delete(synchronize_session=False)

        # 2. Prune old process snapshots (keep last 24 hours of process history)
        proc_cutoff = datetime.now(timezone.utc) - timedelta(hours=min(retention_hours, 24))
        deleted_processes = db.query(MachineProcessSnapshot).filter(
            MachineProcessSnapshot.timestamp < proc_cutoff
        ).delete(synchronize_session=False)

        db.commit()

        stats = {
            "status": "success",
            "retention_hours": retention_hours,
            "cutoff_timestamp": cutoff.isoformat(),
            "deleted_telemetry_points": deleted_telemetry,
            "deleted_process_snapshots": deleted_processes
        }
        if deleted_telemetry > 0 or deleted_processes > 0:
            print(f"[Retention Guardian] Pruned {deleted_telemetry} telemetry points and {deleted_processes} process records older than {cutoff.isoformat()}.")
        return stats
    except Exception as e:
        db.rollback()
        print(f"[Retention Guardian Error] Failed to prune telemetry: {e}")
        return {"status": "error", "error": str(e)}


async def start_retention_loop():
    """
    Background worker loop that runs prune_old_telemetry periodically.
    """
    interval = max(settings.RETENTION_CHECK_INTERVAL_SECONDS, 60)
    print(f"[Retention Guardian] Background worker started. Checking every {interval}s (Retention: {settings.TELEMETRY_RETENTION_HOURS}h).")
    
    # Run once at startup after a brief 5-second warmup
    await asyncio.sleep(5)
    with SessionLocal() as db:
        prune_old_telemetry(db)

    while True:
        try:
            await asyncio.sleep(interval)
            with SessionLocal() as db:
                prune_old_telemetry(db)
        except asyncio.CancelledError:
            print("[Retention Guardian] Worker cancelled cleanly on shutdown.")
            break
        except Exception as e:
            print(f"[Retention Guardian] Unexpected loop error: {e}")
            await asyncio.sleep(60)
