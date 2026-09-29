import json
import uuid
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.evidence import EvidenceArtifact
from app.models.investigation import Investigation
from app.utils.hashing import calculate_file_sha256
from app.services.provenance_service import ProvenanceService

OPERATION_FILENAME_MAP = {
    "SYSTEM.INFO": "system_info.json",
    "PROCESS.LIST": "processes.json",
    "NETWORK.CONNECTIONS": "network_connections.json",
    "DNS.INFO": "dns_info.json",
    "USERS.LIST": "users.json",
    "FILES.RECENT": "recent_files.json",
    "FILE.HASH": "file_hash.json",
    "EVENTLOG.RECENT": "event_log.json",
    "PROCESS.PARENT_CHILD": "process_hierarchy.json",
    "COMMANDLINE.INFO": "commandlines.json"
}

class EvidenceService:
    @staticmethod
    def save_evidence(
        db: Session,
        investigation_id: str,
        round_number: int,
        operation: str,
        collector_name: str,
        data: dict | list,
        reason: str,
        machine_id: str,
        step_id: str | None = None,
        is_synthetic: bool = False
    ) -> EvidenceArtifact:
        """Store forensic evidence to disk, compute SHA-256 hash, and persist artifact + provenance."""
        # 1. Determine storage path
        round_dir = settings.EVIDENCE_DIR / investigation_id / f"round_{round_number}"
        round_dir.mkdir(parents=True, exist_ok=True)

        filename = OPERATION_FILENAME_MAP.get(operation, f"{operation.lower().replace('.', '_')}.json")
        file_path = round_dir / filename

        # 2. Write formatted JSON to disk
        payload = {
            "_forensic_metadata": {
                "investigation_id": investigation_id,
                "operation": operation,
                "collector": collector_name,
                "round": round_number,
                "machine_id": machine_id,
                "reason": reason,
                "is_synthetic": is_synthetic,
                "saved_at": datetime.utcnow().isoformat() + "Z"
            },
            "evidence": data
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

        # 3. Calculate cryptographic hash and file size
        sha256_hash = calculate_file_sha256(file_path)
        file_size = file_path.stat().st_size

        # 4. Generate sequential artifact ID scoped to investigation
        artifact_count = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id
        ).count()
        artifact_id = f"{investigation_id}-EV-{artifact_count + 1:03d}"

        # Fetch investigation intent
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        intent = inv.intent if inv else "unknown"

        artifact = EvidenceArtifact(
            id=artifact_id,
            name=filename,
            artifact_type=f"JSON_{operation.replace('.', '_')}",
            collector=collector_name,
            operation=operation,
            investigation_id=investigation_id,
            step_id=step_id,
            machine_id=machine_id,
            round_number=round_number,
            reason=reason,
            file_path=str(file_path.resolve()),
            file_size_bytes=file_size,
            sha256=sha256_hash,
            integrity_status="VALID",
            is_synthetic=is_synthetic,
            collected_at=datetime.utcnow()
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        # 5. Create immutable provenance record
        ProvenanceService.record_provenance(
            db=db,
            artifact_id=artifact.id,
            investigation_id=investigation_id,
            intent=intent,
            collector=collector_name,
            operation=operation,
            machine_id=machine_id,
            round_number=round_number,
            reason=reason,
            sha256=sha256_hash,
            collected_at=artifact.collected_at,
            metadata={"file_size_bytes": file_size, "is_synthetic": is_synthetic}
        )

        return artifact

    @staticmethod
    def verify_artifact_integrity(db: Session, artifact_id: str) -> dict:
        """Verify an evidence file against its stored SHA-256 cryptographic hash."""
        artifact = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == artifact_id).first()
        if not artifact:
            return {"status": "ERROR", "message": f"Artifact {artifact_id} not found"}

        path = Path(artifact.file_path)
        if not path.is_file():
            artifact.integrity_status = "FILE_MISSING"
            db.commit()
            return {
                "artifact_id": artifact.id,
                "name": artifact.name,
                "status": "FILE_MISSING",
                "expected_hash": artifact.sha256,
                "current_hash": None,
                "verified": False
            }

        current_hash = calculate_file_sha256(path)
        is_valid = (current_hash == artifact.sha256)
        artifact.integrity_status = "VALID" if is_valid else "INTEGRITY_MISMATCH"
        db.commit()

        return {
            "artifact_id": artifact.id,
            "name": artifact.name,
            "status": artifact.integrity_status,
            "expected_hash": artifact.sha256,
            "current_hash": current_hash,
            "verified": is_valid
        }

    @staticmethod
    def verify_all_investigation_evidence(db: Session, investigation_id: str) -> dict:
        """Verify integrity of all artifacts collected in an investigation."""
        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id
        ).all()

        results = []
        all_valid = True
        for art in artifacts:
            res = EvidenceService.verify_artifact_integrity(db, art.id)
            results.append(res)
            if not res["verified"]:
                all_valid = False

        return {
            "investigation_id": investigation_id,
            "total_artifacts": len(artifacts),
            "valid_count": sum(1 for r in results if r["verified"]),
            "all_valid": all_valid,
            "details": results
        }
