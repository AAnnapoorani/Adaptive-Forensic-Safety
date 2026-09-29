"""
JOCKY Forensic Evidence Integrity 2.0 — Cryptographic Hash Chain Service
Constructs and maintains the append-only cryptographic hash chain for evidence artifacts,
generates canonical manifests (jocky-chain.json), and signs chain tips with Ed25519.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.canonical import (
    GENESIS_HASH,
    canonicalize_json,
    canonical_sha256,
    build_canonical_record,
    compute_record_hash,
)
from app.core.key_manager import key_manager
from app.utils.datetime_utils import to_iso_utc
from app.models.evidence import EvidenceArtifact, ProvenanceRecord, EvidenceChainManifest
from app.models.investigation import Investigation


class ChainService:
    """Manages the cryptographic hash chain for forensic investigations."""

    @staticmethod
    def append_artifact_to_chain(
        db: Session,
        artifact: EvidenceArtifact,
        investigation: Investigation,
        reason: str,
        metadata: dict[str, Any] | None = None
    ) -> ProvenanceRecord:
        """
        Append a new evidence artifact to the investigation's cryptographic hash chain.
        Ensures strict sequence continuity, previous-hash binding, and record-hash generation.
        """
        inv_id: str = str(getattr(investigation, "id", "") or "")
        inv_intent: str = str(getattr(investigation, "intent", "") or "")
        inv_script: str = str(getattr(investigation, "script", "") or "")

        art_id: str = str(getattr(artifact, "id", "") or "")
        art_collector: str = str(getattr(artifact, "collector", "") or "")
        art_machine_id: str = str(getattr(artifact, "machine_id", "") or "")
        art_operation: str = str(getattr(artifact, "operation", "") or "")
        art_type: str = str(getattr(artifact, "artifact_type", "") or "")
        art_file_path: str = str(getattr(artifact, "file_path", "") or "")
        art_size: int = int(getattr(artifact, "file_size_bytes", 0) or 0)
        art_sha256: str = str(getattr(artifact, "sha256", "") or "")
        art_round: int = int(getattr(artifact, "round_number", 1) or 1)
        art_reason: str = str(getattr(artifact, "reason", "") or reason or "")
        art_is_synthetic: bool = bool(getattr(artifact, "is_synthetic", False))
        art_collected_at = getattr(artifact, "collected_at", None)

        # 1. Determine previous hash and sequence number
        last_record = db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == inv_id
        ).order_by(ProvenanceRecord.sequence_number.desc()).first()

        last_hash: str = str(getattr(last_record, "record_hash", "") or "") if last_record else ""
        last_seq: int = int(getattr(last_record, "sequence_number", 0) or 0) if last_record else 0

        if last_record is None or not last_hash:
            sequence_number: int = 1
            previous_hash: str = GENESIS_HASH
        else:
            sequence_number = last_seq + 1
            previous_hash = last_hash

        # Active signing key
        active_key_id: str = key_manager.get_or_create_active_key()
        collected_iso: str = to_iso_utc(art_collected_at) or datetime.now(tz=timezone.utc).isoformat()

        # 2. Build canonical record structure (conforming to Integrity 2.0 spec)
        canonical_record = build_canonical_record(
            artifact_id=art_id,
            case_id=inv_id,
            collection_id=inv_id,
            timestamp_utc=collected_iso,
            collector=art_collector,
            host_id=art_machine_id,
            operation=art_operation,
            source="native_win32_collector" if not art_is_synthetic else "demo_dataset",
            artifact_type=art_type,
            file_path=Path(art_file_path).as_posix() if art_file_path else "",
            size=art_size,
            sha256=art_sha256,
            previous_record_hash=previous_hash,
            sequence_number=sequence_number,
            round_number=art_round,
            reason=art_reason,
            key_id=active_key_id,
            jocky_script=inv_script,
            encryption_algorithm="NONE",
            encryption_key_id=""
        )

        # 3. Compute deterministic record hash
        record_hash: str = compute_record_hash(canonical_record, previous_hash)
        canonical_record["record_hash"] = record_hash

        # 4. Sign the record hash with active Ed25519 key
        sig_hex, _ = key_manager.sign_hex(record_hash.encode("utf-8"), active_key_id)
        canonical_record["signature"] = sig_hex

        # 5. Persist ProvenanceRecord
        record_id = f"PROV-{art_id}"
        prov = db.query(ProvenanceRecord).filter(ProvenanceRecord.id == record_id).first()
        metadata_str = json.dumps(canonical_record, default=str)

        if not prov:
            prov = ProvenanceRecord(
                id=record_id,
                artifact_id=art_id,
                investigation_id=inv_id,
                intent=inv_intent,
                collector=art_collector,
                operation=art_operation,
                machine_id=art_machine_id,
                round_number=art_round,
                reason=reason,
                sha256=art_sha256,
                collected_at=art_collected_at,
                recorded_at=datetime.utcnow(),
                metadata_json=metadata_str,
                sequence_number=sequence_number,
                previous_record_hash=previous_hash,
                record_hash=record_hash,
                key_id=active_key_id,
                signature=sig_hex
            )
            db.add(prov)
        else:
            setattr(prov, "sequence_number", sequence_number)
            setattr(prov, "previous_record_hash", previous_hash)
            setattr(prov, "record_hash", record_hash)
            setattr(prov, "key_id", active_key_id)
            setattr(prov, "signature", sig_hex)
            setattr(prov, "metadata_json", metadata_str)

        db.commit()
        db.refresh(prov)

        # 6. Update or create the EvidenceChainManifest
        ChainService.update_chain_manifest(db, inv_id)

        return prov

    @staticmethod
    def update_chain_manifest(db: Session, investigation_id: str) -> EvidenceChainManifest:
        """
        Recompute and sign the chain tip for the given investigation,
        persisting the database manifest and writing jocky-chain.json to disk.
        """
        records = db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == investigation_id
        ).order_by(ProvenanceRecord.sequence_number.asc()).all()

        if not records:
            chain_tip: str = GENESIS_HASH
            record_count: int = 0
            first_ts = None
            last_ts = None
        else:
            chain_tip = str(getattr(records[-1], "record_hash", None) or GENESIS_HASH)
            record_count = len(records)
            first_ts = getattr(records[0], "collected_at", None)
            last_ts = getattr(records[-1], "collected_at", None)

        active_key_id = key_manager.get_or_create_active_key()
        pub_info = key_manager.get_public_key_info(active_key_id)

        # Digital signature of the chain tip binds the entire previous sequence
        tip_sig_hex, _ = key_manager.sign_hex(chain_tip.encode("utf-8"), active_key_id)

        manifest_id = f"CHAIN-{investigation_id}"
        manifest = db.query(EvidenceChainManifest).filter(
            EvidenceChainManifest.investigation_id == investigation_id
        ).first()

        if not manifest:
            manifest = EvidenceChainManifest(
                id=manifest_id,
                investigation_id=investigation_id,
                case_id=investigation_id,
                genesis_hash=GENESIS_HASH,
                chain_tip=chain_tip,
                record_count=record_count,
                first_timestamp=first_ts,
                last_timestamp=last_ts,
                signature_algorithm="Ed25519",
                public_key_pem=pub_info["public_key_pem"],
                public_key_hex=pub_info["public_key_hex"],
                key_id=active_key_id,
                signature_hex=tip_sig_hex
            )
            db.add(manifest)
        else:
            setattr(manifest, "chain_tip", chain_tip)
            setattr(manifest, "record_count", record_count)
            setattr(manifest, "first_timestamp", first_ts)
            setattr(manifest, "last_timestamp", last_ts)
            setattr(manifest, "public_key_pem", pub_info["public_key_pem"])
            setattr(manifest, "public_key_hex", pub_info["public_key_hex"])
            setattr(manifest, "key_id", active_key_id)
            setattr(manifest, "signature_hex", tip_sig_hex)

        db.commit()
        db.refresh(manifest)

        # Write machine-readable jocky-chain.json to investigation directory
        ChainService._write_chain_manifest_file(investigation_id, manifest, records)

        return manifest

    @staticmethod
    def _write_chain_manifest_file(
        investigation_id: str,
        manifest: EvidenceChainManifest,
        records: list[ProvenanceRecord]
    ) -> Path:
        """Save canonical jocky-chain.json in the evidence folder."""
        manifest_dir = settings.EVIDENCE_DIR / investigation_id / "manifests"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        file_path = manifest_dir / "jocky-chain.json"

        record_entries: list[dict[str, Any]] = []
        for r in records:
            meta_raw = getattr(r, "metadata_json", None)
            if meta_raw and isinstance(meta_raw, str):
                try:
                    c_dict = json.loads(meta_raw)
                    c_dict["sequence_number"] = int(getattr(r, "sequence_number", 0) or 0)
                    c_dict["previous_record_hash"] = str(getattr(r, "previous_record_hash", "") or "")
                    c_dict["record_hash"] = str(getattr(r, "record_hash", "") or "")
                    c_dict["signature"] = str(getattr(r, "signature", "") or "")
                    record_entries.append(c_dict)
                    continue
                except Exception:
                    pass

            op_str = str(getattr(r, "operation", "") or "")
            record_entries.append({
                "evidence_id": str(getattr(r, "artifact_id", "") or ""),
                "case_id": str(getattr(r, "investigation_id", "") or ""),
                "collection_id": str(getattr(r, "investigation_id", "") or ""),
                "timestamp_utc": to_iso_utc(getattr(r, "collected_at", None)),
                "collector": str(getattr(r, "collector", "") or ""),
                "host_id": str(getattr(r, "machine_id", "") or ""),
                "operation": op_str,
                "source": "native_collector",
                "artifact_type": f"JSON_{op_str.replace('.', '_')}",
                "file_path": "",
                "size": 0,
                "sha256": str(getattr(r, "sha256", "") or ""),
                "previous_record_hash": str(getattr(r, "previous_record_hash", "") or ""),
                "record_hash": str(getattr(r, "record_hash", "") or ""),
                "sequence_number": int(getattr(r, "sequence_number", 0) or 0),
                "round_number": int(getattr(r, "round_number", 1) or 1),
                "key_id": str(getattr(r, "key_id", "") or ""),
                "signature": str(getattr(r, "signature", "") or ""),
                "encryption": {"algorithm": "NONE", "key_id": ""}
            })

        manifest_dict = {
            "format": "JOCKY-EVIDENCE-CHAIN",
            "version": "2.0",
            "case_id": str(getattr(manifest, "case_id", "") or ""),
            "investigation_id": str(getattr(manifest, "investigation_id", "") or ""),
            "genesis_hash": str(getattr(manifest, "genesis_hash", "") or ""),
            "record_count": int(getattr(manifest, "record_count", 0) or 0),
            "first_timestamp": to_iso_utc(getattr(manifest, "first_timestamp", None)),
            "last_timestamp": to_iso_utc(getattr(manifest, "last_timestamp", None)),
            "chain_tip": str(getattr(manifest, "chain_tip", "") or ""),
            "signature_algorithm": str(getattr(manifest, "signature_algorithm", "") or ""),
            "key_id": str(getattr(manifest, "key_id", "") or ""),
            "public_key_hex": str(getattr(manifest, "public_key_hex", "") or ""),
            "public_key_pem": str(getattr(manifest, "public_key_pem", "") or ""),
            "signature": str(getattr(manifest, "signature_hex", "") or ""),
            "records": record_entries
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=2)

        return file_path

    @staticmethod
    def get_chain_records(db: Session, investigation_id: str) -> list[dict[str, Any]]:
        """Retrieve ordered list of chain records for UI/API consumption."""
        records = db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == investigation_id
        ).order_by(ProvenanceRecord.sequence_number.asc()).all()

        results = []
        for idx, r in enumerate(records):
            c_dict = None
            meta_raw = getattr(r, "metadata_json", None)
            if meta_raw and isinstance(meta_raw, str):
                try:
                    c_dict = json.loads(meta_raw)
                except Exception:
                    pass

            seq = getattr(r, "sequence_number", None)
            rec_hash = getattr(r, "record_hash", "") or ""

            results.append({
                "sequence_number": int(seq) if seq is not None else idx + 1,
                "artifact_id": getattr(r, "artifact_id", ""),
                "operation": getattr(r, "operation", ""),
                "collector": getattr(r, "collector", ""),
                "round_number": getattr(r, "round_number", 1),
                "reason": getattr(r, "reason", ""),
                "sha256": getattr(r, "sha256", ""),
                "previous_record_hash": getattr(r, "previous_record_hash", "") or GENESIS_HASH,
                "record_hash": rec_hash,
                "key_id": getattr(r, "key_id", "") or "",
                "signature": getattr(r, "signature", "") or "",
                "collected_at": to_iso_utc(getattr(r, "collected_at", None)),
                "recorded_at": to_iso_utc(getattr(r, "recorded_at", None)),
                "is_legacy": not bool(rec_hash),
                "canonical_record": c_dict
            })
        return results

    @staticmethod
    def get_manifest_dict(db: Session, investigation_id: str) -> dict[str, Any] | None:
        """Get the full chain manifest dictionary."""
        manifest = db.query(EvidenceChainManifest).filter(
            EvidenceChainManifest.investigation_id == investigation_id
        ).first()

        if not manifest:
            records = db.query(ProvenanceRecord).filter(
                ProvenanceRecord.investigation_id == investigation_id
            ).all()
            if records:
                manifest = ChainService.update_chain_manifest(db, investigation_id)
            else:
                return None

        # Read the file directly if present
        manifest_file = settings.EVIDENCE_DIR / investigation_id / "manifests" / "jocky-chain.json"
        if manifest_file.is_file():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        return {
            "format": "JOCKY-EVIDENCE-CHAIN",
            "version": "2.0",
            "case_id": getattr(manifest, "case_id", ""),
            "investigation_id": getattr(manifest, "investigation_id", ""),
            "genesis_hash": getattr(manifest, "genesis_hash", ""),
            "record_count": getattr(manifest, "record_count", 0),
            "first_timestamp": to_iso_utc(getattr(manifest, "first_timestamp", None)),
            "last_timestamp": to_iso_utc(getattr(manifest, "last_timestamp", None)),
            "chain_tip": getattr(manifest, "chain_tip", ""),
            "signature_algorithm": getattr(manifest, "signature_algorithm", ""),
            "key_id": getattr(manifest, "key_id", ""),
            "public_key_hex": getattr(manifest, "public_key_hex", ""),
            "public_key_pem": getattr(manifest, "public_key_pem", ""),
            "signature": getattr(manifest, "signature_hex", ""),
            "records": ChainService.get_chain_records(db, investigation_id)
        }
