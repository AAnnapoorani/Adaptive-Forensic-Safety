import json
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.evidence import EvidenceArtifact, ProvenanceRecord
from app.models.investigation import Investigation
from app.core.canonical import GENESIS_HASH, compute_record_hash
from app.core.key_manager import key_manager
from app.utils.datetime_utils import to_iso_utc


class ProvenanceService:
    @staticmethod
    def record_provenance(
        db: Session,
        artifact_id: str,
        investigation_id: str,
        intent: str,
        collector: str,
        operation: str,
        machine_id: str,
        round_number: int,
        reason: str,
        sha256: str,
        collected_at: datetime | None = None,
        metadata: dict | None = None
    ) -> ProvenanceRecord:
        """
        Create a cryptographically hash-chained provenance record conforming to
        JOCKY Evidence Integrity 2.0 standards.
        """
        from app.services.chain_service import ChainService

        artifact = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == artifact_id).first()
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()

        if artifact and inv:
            return ChainService.append_artifact_to_chain(
                db=db,
                artifact=artifact,
                investigation=inv,
                reason=reason,
                metadata=metadata
            )

        # Fallback if artifact object not yet flushed
        last_record = db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == investigation_id
        ).order_by(ProvenanceRecord.sequence_number.desc()).first()

        if last_record is None or not last_record.record_hash:
            sequence_number = 1
            previous_hash = GENESIS_HASH
        else:
            sequence_number = last_record.sequence_number + 1
            previous_hash = last_record.record_hash

        active_key_id = key_manager.get_or_create_active_key()
        collected_dt = collected_at or datetime.utcnow()
        collected_iso = to_iso_utc(collected_dt)

        canonical_record_dict = {
            "artifact_id": artifact_id,
            "artifact_type": f"JSON_{operation.replace('.', '_')}",
            "case_id": investigation_id,
            "collected_at": collected_iso,
            "collector": collector,
            "file_path": metadata.get("file_path", "") if metadata else "",
            "file_size_bytes": metadata.get("file_size_bytes", 0) if metadata else 0,
            "host_id": machine_id,
            "investigation_id": investigation_id,
            "is_synthetic": bool(metadata.get("is_synthetic", False)) if metadata else False,
            "jocky_operation": operation,
            "key_id": active_key_id,
            "previous_record_hash": previous_hash,
            "reason": reason,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "sha256": sha256,
        }

        record_hash = compute_record_hash(canonical_record_dict, previous_hash)
        sig_hex, _ = key_manager.sign_hex(record_hash.encode("utf-8"), active_key_id)

        record_id = f"PROV-{artifact_id}"
        prov = ProvenanceRecord(
            id=record_id,
            artifact_id=artifact_id,
            investigation_id=investigation_id,
            intent=intent,
            collector=collector,
            operation=operation,
            machine_id=machine_id,
            round_number=round_number,
            reason=reason,
            sha256=sha256,
            collected_at=collected_dt,
            recorded_at=datetime.utcnow(),
            metadata_json=json.dumps(metadata or {}, default=str),
            sequence_number=sequence_number,
            previous_record_hash=previous_hash,
            record_hash=record_hash,
            key_id=active_key_id,
            signature=sig_hex
        )
        db.add(prov)
        db.commit()
        db.refresh(prov)

        try:
            ChainService.update_chain_manifest(db, investigation_id)
        except Exception:
            pass

        return prov

    @staticmethod
    def get_provenance_for_artifact(db: Session, artifact_id: str) -> ProvenanceRecord | None:
        """Retrieve full lineage for a specific evidence artifact."""
        return db.query(ProvenanceRecord).filter(ProvenanceRecord.artifact_id == artifact_id).first()

    @staticmethod
    def get_investigation_provenance(db: Session, investigation_id: str) -> list[ProvenanceRecord]:
        """Retrieve all provenance records for an entire investigation in sequence."""
        return db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == investigation_id
        ).order_by(ProvenanceRecord.sequence_number.asc()).all()
