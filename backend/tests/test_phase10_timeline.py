import sys
from pathlib import Path
from datetime import datetime

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.core.database import SessionLocal, init_db
from app.models.machine import Machine
from app.models.investigation import Investigation, InvestigationRound
from app.services.evidence_service import EvidenceService
from app.services.timeline_service import TimelineService

def test_phase10_timeline_engine():
    print("Testing Phase 10: Forensic Timeline Normalization & Chronological Ordering...")
    init_db()
    db = SessionLocal()

    try:
        # 1. Setup machine and investigation
        machine = db.query(Machine).first()
        if not machine:
            machine = Machine(id="MACHINE-TL", hostname="tl-host", os_name="Windows", status="ACTIVE")
            db.add(machine)
            db.commit()

        inv = Investigation(
            id="INV-TL-TEST",
            intent="suspicious_network_activity",
            machine_id=machine.id,
            status="IN_PROGRESS"
        )
        db.merge(inv)
        
        # Add Round milestone
        rnd = InvestigationRound(
            id="RND-TL-01",
            investigation_id=inv.id,
            round_number=1,
            trigger_reason="Initial investigation requirement",
            status="COMPLETED",
            started_at=datetime.utcnow()
        )
        db.merge(rnd)
        db.commit()

        # 2. Save Evidence Artifacts
        procs = [
            {"pid": 100, "name": "explorer.exe", "create_time_iso": "2026-09-25T03:00:00Z"},
            {"pid": 500, "name": "powershell.exe", "create_time_iso": "2026-09-25T03:15:00Z"}
        ]
        EvidenceService.save_evidence(
            db=db,
            investigation_id=inv.id,
            round_number=1,
            operation="PROCESS.LIST",
            collector_name="Process List Collector",
            data=procs,
            reason="Initial requirement",
            machine_id=machine.id
        )

        conns = [
            {
                "local_address": "192.168.1.50",
                "local_port": 49152,
                "remote_address": "203.0.113.10",
                "remote_port": 443,
                "status": "ESTABLISHED",
                "pid": 500,
                "process_name": "powershell.exe"
            }
        ]
        EvidenceService.save_evidence(
            db=db,
            investigation_id=inv.id,
            round_number=1,
            operation="NETWORK.CONNECTIONS",
            collector_name="Network Connections Collector",
            data=conns,
            reason="Initial requirement",
            machine_id=machine.id
        )

        # 3. Generate Timeline
        events = TimelineService.generate_timeline(db, inv.id, machine.id)
        assert len(events) >= 3

        # 4. Verify Chronological Ordering
        for i in range(len(events) - 1):
            assert events[i].timestamp <= events[i+1].timestamp, "Timeline events must be strictly chronological"

        event_types = {e.event_type for e in events}
        assert "PROCESS_CREATED" in event_types
        assert "NETWORK_SOCKET_ACTIVE" in event_types
        assert "WORKFLOW_ROUND_STARTED" in event_types

        print(f"[PASS] Timeline synthesized {len(events)} events in chronological order:")
        for ev in events[:5]:
            print(f"       -> [{ev.timestamp.isoformat()}] ({ev.source}) {ev.event_type}: {ev.description[:60]}...")

    finally:
        db.close()

if __name__ == "__main__":
    test_phase10_timeline_engine()
    print("\n>>> ALL PHASE 10 TIMELINE ENGINE TESTS PASSED SUCCESSFULLY! <<<\n")
