import os
import shutil
from pathlib import Path
from app.core.database import SessionLocal, init_db
from app.core.config import settings
from app.models import (
    ProvenanceRecord,
    EvidenceChainManifest,
    EvidenceArtifact,
    TimelineEvent,
    CorrelationMatch,
    EscalationAction,
    ExecutionLog,
    WorkflowStep,
    InvestigationRound,
    Investigation,
    Machine,
)
from app.utils.platform import get_machine_info

def reset_all():
    print("=" * 60)
    print("JOCKY Database Reset Utility")
    print("=" * 60)
    
    init_db()
    db = SessionLocal()
    try:
        # Delete dependent child tables first to respect foreign keys
        deleted_prov = db.query(ProvenanceRecord).delete()
        deleted_mani = db.query(EvidenceChainManifest).delete()
        deleted_art = db.query(EvidenceArtifact).delete()
        deleted_time = db.query(TimelineEvent).delete()
        deleted_corr = db.query(CorrelationMatch).delete()
        deleted_esca = db.query(EscalationAction).delete()
        deleted_exec = db.query(ExecutionLog).delete()
        deleted_step = db.query(WorkflowStep).delete()
        deleted_rnd = db.query(InvestigationRound).delete()
        deleted_inv = db.query(Investigation).delete()
        deleted_mach = db.query(Machine).delete()

        # Re-register local active machine so the system remains healthy
        info = get_machine_info()
        machine = Machine(
            id=info["id"],
            hostname=info["hostname"],
            os_name=info["os_name"],
            os_version=info["os_version"],
            architecture=info["architecture"],
            ip_address=info["ip_address"],
            status="ACTIVE"
        )
        db.add(machine)
        db.commit()

        print(f"Database rows cleared successfully:")
        print(f"  • Investigations:         {deleted_inv}")
        print(f"  • Investigation Rounds:    {deleted_rnd}")
        print(f"  • Workflow Steps:          {deleted_step}")
        print(f"  • Evidence Artifacts:      {deleted_art}")
        print(f"  • Provenance Records:      {deleted_prov}")
        print(f"  • Chain Manifests:         {deleted_mani}")
        print(f"  • Timeline Events:         {deleted_time}")
        print(f"  • Correlation Matches:     {deleted_corr}")
        print(f"  • Escalation Actions:      {deleted_esca}")
        print(f"  • Execution Logs:          {deleted_exec}")
        print(f"  • Old Machines:            {deleted_mach}")
        print(f"  • Active Machine:          Registered {machine.id} ({machine.hostname})")

    except Exception as e:
        db.rollback()
        print(f"Error resetting database: {e}")
        raise
    finally:
        db.close()

    # Clean up evidence directory folders (INV-*) while preserving safe_scan and .gitkeep
    evidence_dir = settings.EVIDENCE_DIR
    if evidence_dir.exists():
        for item in evidence_dir.iterdir():
            if item.is_dir() and item.name.startswith("INV-"):
                try:
                    shutil.rmtree(item)
                    print(f"  • Removed file evidence:   {item.name}")
                except Exception as e:
                    print(f"  • Warning removing {item.name}: {e}")

    print("\n[SUCCESS] All data in the database and evidence storage has been deleted.")

if __name__ == "__main__":
    reset_all()
