import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.evidence import EvidenceArtifact, ProvenanceRecord, EvidenceChainManifest
from app.services.evidence_service import EvidenceService
from app.services.chain_service import ChainService
from app.services.verifier_service import VerifierService
from app.services.export_service import ExportService
from app.core.key_manager import key_manager
from app.utils.datetime_utils import to_iso_utc

router = APIRouter(tags=["Evidence & Provenance (Integrity 2.0)"])

@router.get("/investigations/{investigation_id}/evidence")
def list_investigation_evidence(investigation_id: str, db: Session = Depends(get_db)):
    """List all evidence artifacts gathered during an investigation."""
    artifacts = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.investigation_id == investigation_id
    ).order_by(EvidenceArtifact.round_number.asc(), EvidenceArtifact.collected_at.asc()).all()

    return [
        {
            "id": getattr(a, "id", ""),
            "name": getattr(a, "name", ""),
            "artifact_type": getattr(a, "artifact_type", ""),
            "collector": getattr(a, "collector", ""),
            "operation": getattr(a, "operation", ""),
            "round_number": getattr(a, "round_number", 1),
            "reason": getattr(a, "reason", ""),
            "file_size_bytes": getattr(a, "file_size_bytes", 0),
            "sha256": getattr(a, "sha256", ""),
            "integrity_status": getattr(a, "integrity_status", ""),
            "is_synthetic": getattr(a, "is_synthetic", False),
            "collected_at": to_iso_utc(getattr(a, "collected_at", None))
        }
        for a in artifacts
    ]

@router.get("/investigations/{investigation_id}/provenance")
def get_investigation_provenance(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve full immutable forensic provenance ledger with cryptographic hash chaining."""
    records = db.query(ProvenanceRecord).filter(
        ProvenanceRecord.investigation_id == investigation_id
    ).order_by(ProvenanceRecord.sequence_number.asc(), ProvenanceRecord.recorded_at.asc()).all()

    return [
        {
            "id": getattr(p, "id", ""),
            "artifact_id": getattr(p, "artifact_id", ""),
            "sequence_number": int(getattr(p, "sequence_number", 0) or idx + 1),
            "intent": getattr(p, "intent", ""),
            "collector": getattr(p, "collector", ""),
            "operation": getattr(p, "operation", ""),
            "machine_id": getattr(p, "machine_id", ""),
            "round_number": getattr(p, "round_number", 1),
            "reason": getattr(p, "reason", ""),
            "sha256": getattr(p, "sha256", ""),
            "previous_record_hash": getattr(p, "previous_record_hash", ""),
            "record_hash": getattr(p, "record_hash", ""),
            "key_id": getattr(p, "key_id", ""),
            "signature": getattr(p, "signature", ""),
            "is_legacy": not bool(getattr(p, "record_hash", None)),
            "collected_at": to_iso_utc(getattr(p, "collected_at", None)),
            "recorded_at": to_iso_utc(getattr(p, "recorded_at", None)),
            "metadata": json.loads(str(getattr(p, "metadata_json", ""))) if getattr(p, "metadata_json", None) else {}
        }
        for idx, p in enumerate(records)
    ]

@router.post("/investigations/{investigation_id}/verify")
def verify_evidence_integrity(investigation_id: str, db: Session = Depends(get_db)):
    """Re-compute cryptographic SHA-256 hashes of all artifacts and report integrity."""
    return EvidenceService.verify_all_investigation_evidence(db, investigation_id)

# ─── Evidence Integrity 2.0 Endpoints ────────────────────────────────────────

@router.get("/investigations/{investigation_id}/chain")
def get_investigation_chain(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve the full cryptographic hash chain records for an investigation."""
    records = ChainService.get_chain_records(db, investigation_id)
    manifest = ChainService.get_manifest_dict(db, investigation_id)
    return {
        "investigation_id": investigation_id,
        "manifest": manifest,
        "records": records
    }

@router.get("/investigations/{investigation_id}/chain/manifest")
def get_chain_manifest(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve machine-readable jocky-chain.json manifest."""
    manifest = ChainService.get_manifest_dict(db, investigation_id)
    if not manifest:
        raise HTTPException(status_code=404, detail="Chain manifest not found.")
    return manifest

@router.post("/investigations/{investigation_id}/chain/verify")
def verify_chain(investigation_id: str, db: Session = Depends(get_db)):
    """
    Perform 7-pass comprehensive cryptographic verification on the investigation:
    evidence hashes, canonical metadata, hash chain links, sequence order, chain tip, and Ed25519 signature.
    """
    report = VerifierService.verify_investigation_chain(db, investigation_id)
    return report

@router.post("/investigations/{investigation_id}/chain/sign")
def sign_chain_tip(investigation_id: str, db: Session = Depends(get_db)):
    """Sign the latest chain tip using the authorized active Ed25519 key."""
    manifest = ChainService.update_chain_manifest(db, investigation_id)
    return {
        "status": "SIGNED",
        "investigation_id": investigation_id,
        "chain_tip": manifest.chain_tip,
        "key_id": manifest.key_id,
        "signature_hex": manifest.signature_hex,
        "algorithm": "Ed25519"
    }

@router.get("/investigations/{investigation_id}/chain/export")
def export_forensic_package(investigation_id: str, db: Session = Depends(get_db)):
    """Download portable, self-contained forensic package (.zip) for offline court verification."""
    try:
        zip_buf = ExportService.create_forensic_package(db, investigation_id)
        filename = f"forensic_package_{investigation_id}.zip"
        return Response(
            content=zip_buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate forensic package: {str(e)}")

# ─── Ed25519 Key Management Endpoints ────────────────────────────────────────

@router.get("/evidence/keys")
def list_public_keys():
    """List registered public keys and current active signing key (audit safe, no private keys)."""
    return {
        "active_key_id": key_manager.get_or_create_active_key(),
        "keys": key_manager.list_public_keys()
    }

@router.post("/evidence/keys/rotate")
def rotate_signing_key(alias: str | None = None):
    """Rotate active Ed25519 signing key. Historical keys remain valid for verification."""
    new_key_id = key_manager.rotate_key(alias=alias)
    info = key_manager.get_public_key_info(new_key_id)
    return {
        "status": "KEY_ROTATED",
        "active_key_id": new_key_id,
        "public_key_hex": info["public_key_hex"],
        "algorithm": "Ed25519"
    }

# ─── Raw Artifact Content Endpoint ───────────────────────────────────────────

@router.get("/evidence/{artifact_id}/raw")
def get_raw_artifact_content(artifact_id: str, db: Session = Depends(get_db)):
    """Fetch raw evidence JSON payload from disk."""
    artifact = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    file_path_str = str(getattr(artifact, "file_path", "") or "")
    p = Path(file_path_str)
    if not p.is_file():
        from app.core.config import settings
        inv_id = str(getattr(artifact, "investigation_id", "") or "")
        rnd = getattr(artifact, "round_number", 1)
        art_name = str(getattr(artifact, "name", "") or "")
        fallback_p = settings.EVIDENCE_DIR / inv_id / f"round_{rnd}" / art_name
        if fallback_p.is_file():
            p = fallback_p
        else:
            raise HTTPException(status_code=404, detail=f"File on disk missing: {file_path_str}")

    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data
