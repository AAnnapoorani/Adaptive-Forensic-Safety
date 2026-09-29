import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.core.database import SessionLocal, init_db
from app.models.machine import Machine
from app.models.investigation import Investigation
from app.services.evidence_service import EvidenceService
from app.services.provenance_service import ProvenanceService

def test_phase3_evidence_management():
    print("Testing Phase 3: Evidence Management, SHA-256, and Provenance...")
    init_db()
    db = SessionLocal()

    try:
        # 1. Setup test machine and investigation
        machine = db.query(Machine).first()
        if not machine:
            machine = Machine(id="MACHINE-TEST", hostname="test-host", os_name="Windows", status="ACTIVE")
            db.add(machine)
            db.commit()

        inv = Investigation(
            id="INV-TEST-001",
            intent="suspicious_network_activity",
            machine_id=machine.id,
            status="IN_PROGRESS"
        )
        db.merge(inv)
        db.commit()

        # 2. Save Evidence Artifact
        sample_data = [{"pid": 1234, "name": "powershell.exe", "cmdline": "powershell -enc..."}]
        artifact = EvidenceService.save_evidence(
            db=db,
            investigation_id=inv.id,
            round_number=1,
            operation="PROCESS.LIST",
            collector_name="Process List Collector",
            data=sample_data,
            reason="Initial investigation requirement",
            machine_id=machine.id
        )

        assert "EV-" in artifact.id
        assert Path(artifact.file_path).is_file()
        assert len(artifact.sha256) == 64
        print(f"[PASS] Saved artifact {artifact.id} ({artifact.name}) with SHA-256: {artifact.sha256[:16]}...")

        # 3. Verify Provenance Record was automatically created
        prov = ProvenanceService.get_provenance_for_artifact(db, artifact.id)
        assert prov is not None
        assert prov.sha256 == artifact.sha256
        assert prov.reason == "Initial investigation requirement"
        assert prov.round_number == 1
        print(f"[PASS] Provenance record verified: ID={prov.id}, Collector={prov.collector}")

        # 4. Integrity Check (Valid State)
        check = EvidenceService.verify_artifact_integrity(db, artifact.id)
        assert check["status"] == "VALID"
        assert check["verified"] is True
        print("[PASS] Evidence integrity verification: VALID")

        # 5. Tamper Detection Check
        # Artificially alter the file content to simulate corruption/tampering
        with open(artifact.file_path, "a") as f:
            f.write("\n# TAMPER_TEST")

        tamper_check = EvidenceService.verify_artifact_integrity(db, artifact.id)
        assert tamper_check["status"] == "INTEGRITY_MISMATCH"
        assert tamper_check["verified"] is False
        print("[PASS] Tamper detection successfully flagged: INTEGRITY_MISMATCH")

    finally:
        db.close()

if __name__ == "__main__":
    test_phase3_evidence_management()
    print("\n>>> ALL PHASE 3 EVIDENCE & PROVENANCE TESTS PASSED SUCCESSFULLY! <<<\n")
