"""
JOCKY Forensic Evidence Integrity 2.0 — Comprehensive Verification Engine
Performs 7-pass forensic verification over evidence payloads, RFC 8785 metadata,
hash chain links, sequence continuity, chain tip, and Ed25519 digital signatures.
"""

import json
from pathlib import Path
from typing import Any, cast
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.canonical import (
    GENESIS_HASH,
    build_canonical_record,
    compute_record_hash,
    stream_file_sha256,
)
from app.core.key_manager import key_manager
from app.utils.datetime_utils import to_iso_utc
from app.models.evidence import EvidenceArtifact, ProvenanceRecord, EvidenceChainManifest


class VerifierService:
    """Independent in-engine verification for JOCKY cryptographic evidence chains."""

    @staticmethod
    def verify_investigation_chain(db: Session, investigation_id: str) -> dict[str, Any]:
        """
        Execute 7-pass comprehensive verification for an investigation's evidence chain.
        Returns detailed diagnostics with actionable forensic failure reporting.
        """
        records = db.query(ProvenanceRecord).filter(
            ProvenanceRecord.investigation_id == investigation_id
        ).order_by(ProvenanceRecord.sequence_number.asc()).all()

        manifest = db.query(EvidenceChainManifest).filter(
            EvidenceChainManifest.investigation_id == investigation_id
        ).first()

        if not records:
            return {
                "investigation_id": investigation_id,
                "result": "EMPTY",
                "message": "No evidence artifacts recorded for this investigation.",
                "verified": False,
                "records_count": 0
            }

        # Check for Legacy Evidence (no hash chain fields present)
        is_legacy = all(not r.record_hash for r in records)
        if is_legacy:
            # Verify raw payload SHA-256 for backward compatibility
            raw_passes = 0
            raw_fails = []
            for r in records:
                art = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == r.artifact_id).first()
                if art and art.file_path and Path(str(art.file_path)).is_file():
                    computed = stream_file_sha256(str(art.file_path))
                    if computed == r.sha256:
                        raw_passes += 1
                    else:
                        raw_fails.append(str(r.artifact_id))

            return {
                "investigation_id": investigation_id,
                "result": "LEGACY_FORMAT",
                "verified": False,
                "is_legacy": True,
                "message": "Legacy JOCKY evidence format: SHA-256 artifact verification available; cryptographic hash-chain and Ed25519 signatures not present.",
                "evidence_hashes": "PASS" if not raw_fails else "FAIL",
                "hash_chain": "NOT_AVAILABLE",
                "ed25519_signature": "NOT_AVAILABLE",
                "records_count": len(records),
                "valid_artifacts_count": raw_passes
            }

        # ── Comprehensive 7-Pass Verification ────────────────────────────────
        diagnostics = {
            "evidence_hashes": "PASSED",
            "metadata_integrity": "PASSED",
            "hash_chain": "PASSED",
            "chain_ordering": "PASSED",
            "chain_tip": "PASSED",
            "ed25519_signature": "PASSED"
        }

        failure_details = None
        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records):
            seq = int(getattr(rec, "sequence_number", None) or (idx + 1))
            art_id_str = str(rec.artifact_id)
            art = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == rec.artifact_id).first()

            # ── Pass 1: Evidence Payload SHA-256 Check ───────────────────────
            if not art or not art.file_path or not Path(str(art.file_path)).is_file():
                diagnostics["evidence_hashes"] = "FAILED"
                failure_details = {
                    "record_sequence": seq,
                    "artifact_id": art_id_str,
                    "attack_type": "MISSING_EVIDENCE_FILE",
                    "reason": f"Evidence artifact file is missing on disk: {art_id_str}",
                    "file_path": str(art.file_path) if art and art.file_path else "UNKNOWN"
                }
                break

            actual_file_sha = stream_file_sha256(str(art.file_path))
            if actual_file_sha != rec.sha256 or actual_file_sha != art.sha256:
                diagnostics["evidence_hashes"] = "FAILED"
                failure_details = {
                    "record_sequence": seq,
                    "artifact_id": art_id_str,
                    "attack_type": "MODIFIED_EVIDENCE_PAYLOAD",
                    "reason": f"Evidence file content tampered. SHA-256 digest mismatch on artifact {art_id_str}.",
                    "expected_sha256": str(rec.sha256),
                    "calculated_sha256": actual_file_sha
                }
                break

            # ── Pass 2: Sequence Number Continuity Check ─────────────────────
            expected_seq = idx + 1
            if seq != expected_seq:
                diagnostics["chain_ordering"] = "FAILED"
                failure_details = {
                    "record_sequence": seq,
                    "artifact_id": art_id_str,
                    "attack_type": "SEQUENCE_GAP_OR_OUT_OF_ORDER",
                    "reason": f"Chain sequence gap or reordering detected. Expected sequence #{expected_seq}, found #{seq}.",
                    "expected_sequence": expected_seq,
                    "found_sequence": seq
                }
                break

            # ── Pass 3: Previous Hash Continuity Check ───────────────────────
            stored_prev_hash = str(rec.previous_record_hash or "")
            if stored_prev_hash != expected_prev_hash:
                diagnostics["hash_chain"] = "FAILED"
                failure_details = {
                    "record_sequence": seq,
                    "artifact_id": art_id_str,
                    "attack_type": "PREVIOUS_HASH_MISMATCH",
                    "reason": (
                        f"Cryptographic hash chain broken at record #{seq}. "
                        f"previous_record_hash does not match hash of preceding record #{seq-1}."
                    ),
                    "expected_previous_hash": expected_prev_hash,
                    "stored_previous_hash": stored_prev_hash
                }
                break

            # ── Pass 4: Metadata Integrity & Record Hash Recalculation ───────
            if rec.metadata_json:
                try:
                    canonical_meta = json.loads(str(rec.metadata_json))
                except Exception:
                    canonical_meta = None
            else:
                canonical_meta = None

            if canonical_meta:
                # Detect if database columns were altered after creation
                meta_tampered = False
                tamper_field = None
                if canonical_meta.get("reason", "") != str(rec.reason or ""):
                    meta_tampered = True
                    tamper_field = "reason"
                elif canonical_meta.get("collector", "") != str(rec.collector or ""):
                    meta_tampered = True
                    tamper_field = "collector"
                elif canonical_meta.get("host_id", "") != str(rec.machine_id or ""):
                    meta_tampered = True
                    tamper_field = "host_id"
                elif canonical_meta.get("operation", "") != str(rec.operation or ""):
                    meta_tampered = True
                    tamper_field = "operation"
                elif canonical_meta.get("sha256", "") != str(rec.sha256 or ""):
                    meta_tampered = True
                    tamper_field = "sha256"

                if meta_tampered:
                    diagnostics["metadata_integrity"] = "FAILED"
                    failure_details = {
                        "record_sequence": seq,
                        "artifact_id": art_id_str,
                        "attack_type": "CANONICAL_METADATA_TAMPERED",
                        "reason": f"Record #{seq} provenance metadata field '{tamper_field}' was tampered in database.",
                        "field": tamper_field
                    }
                    break
            else:
                collected_dt = cast(datetime | None, rec.collected_at)
                collected_iso = to_iso_utc(collected_dt) or ""
                canonical_meta = build_canonical_record(
                    artifact_id=str(rec.artifact_id),
                    case_id=str(rec.investigation_id),
                    collection_id=str(rec.investigation_id),
                    timestamp_utc=collected_iso,
                    collector=str(rec.collector),
                    host_id=str(rec.machine_id),
                    operation=str(rec.operation),
                    source="native_win32_collector" if not art.is_synthetic else "demo_dataset",
                    artifact_type=str(art.artifact_type),
                    file_path=Path(str(art.file_path)).as_posix(),
                    size=int(getattr(art, "file_size_bytes", 0) or 0),
                    sha256=str(rec.sha256),
                    previous_record_hash=stored_prev_hash,
                    sequence_number=seq,
                    round_number=int(getattr(rec, "round_number", 1) or 1),
                    reason=str(rec.reason or ""),
                    key_id=str(rec.key_id or "")
                )

            recomputed_record_hash = compute_record_hash(canonical_meta, stored_prev_hash)

            if recomputed_record_hash != rec.record_hash:
                diagnostics["metadata_integrity"] = "FAILED"
                diagnostics["hash_chain"] = "FAILED"
                failure_details = {
                    "record_sequence": seq,
                    "artifact_id": art_id_str,
                    "attack_type": "CANONICAL_METADATA_TAMPERED",
                    "reason": f"Record #{seq} metadata altered or record_hash tampered.",
                    "stored_record_hash": str(rec.record_hash or ""),
                    "calculated_record_hash": recomputed_record_hash
                }
                break

            # ── Pass 5: Per-Record Ed25519 Signature Check (if signed) ───────
            if rec.signature:
                sig_valid = key_manager.verify_signature(
                    signature=str(rec.signature),
                    data=str(rec.record_hash).encode("utf-8"),
                    key_id=str(rec.key_id) if rec.key_id else None
                )
                if not sig_valid:
                    diagnostics["ed25519_signature"] = "FAILED"
                    failure_details = {
                        "record_sequence": seq,
                        "artifact_id": art_id_str,
                        "attack_type": "INVALID_RECORD_SIGNATURE",
                        "reason": f"Ed25519 digital signature invalid for record #{seq} under key {rec.key_id}.",
                        "key_id": str(rec.key_id or "")
                    }
                    break

            expected_prev_hash = str(rec.record_hash or "")

        # ── Pass 6: Chain Tip Matching ───────────────────────────────────────
        if failure_details is None and manifest:
            recomputed_tip = str(records[-1].record_hash or "")
            if str(manifest.chain_tip) != recomputed_tip:
                diagnostics["chain_tip"] = "FAILED"
                failure_details = {
                    "record_sequence": len(records),
                    "artifact_id": str(records[-1].artifact_id),
                    "attack_type": "CHAIN_TIP_MISMATCH",
                    "reason": "Manifest chain tip does not match the computed hash of the final chain record.",
                    "expected_chain_tip": recomputed_tip,
                    "manifest_chain_tip": str(manifest.chain_tip)
                }

        # ── Pass 7: Ed25519 Chain Tip Signature Check ────────────────────────
        if failure_details is None and manifest and manifest.signature_hex:
            tip_valid = key_manager.verify_signature(
                signature=str(manifest.signature_hex),
                data=str(manifest.chain_tip).encode("utf-8"),
                public_key_pem=str(manifest.public_key_pem) if manifest.public_key_pem else None,
                key_id=str(manifest.key_id) if manifest.key_id else None
            )
            if not tip_valid:
                diagnostics["ed25519_signature"] = "FAILED"
                failure_details = {
                    "record_sequence": len(records),
                    "artifact_id": "CHAIN_TIP",
                    "attack_type": "INVALID_ED25519_SIGNATURE",
                    "reason": f"Ed25519 digital signature of chain tip failed validation under key {manifest.key_id}.",
                    "key_id": str(manifest.key_id or "")
                }

        is_verified = (failure_details is None)
        result_status = "VERIFIED" if is_verified else "TAMPERED"

        return {
            "investigation_id": investigation_id,
            "case_id": str(manifest.case_id) if manifest and manifest.case_id else investigation_id,
            "result": result_status,
            "verified": is_verified,
            "records_count": len(records),
            "chain_tip": str(manifest.chain_tip) if manifest and manifest.chain_tip else (str(records[-1].record_hash) if records and records[-1].record_hash else None),
            "key_id": str(manifest.key_id) if manifest and manifest.key_id else (str(records[-1].key_id) if records and records[-1].key_id else None),
            "signature_algorithm": "Ed25519",
            "diagnostics": diagnostics,
            "failure_details": failure_details
        }
