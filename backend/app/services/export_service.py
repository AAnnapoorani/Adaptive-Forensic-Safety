"""
JOCKY Forensic Evidence Integrity 2.0 — Portable Forensic Export Service
Packages an investigation's evidence artifacts, canonical manifests, Ed25519 signatures,
public keys, verification reports, and standalone verification CLI into a self-contained ZIP archive.
"""

import io
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.investigation import Investigation
from app.models.evidence import EvidenceArtifact, EvidenceChainManifest
from app.services.chain_service import ChainService
from app.services.verifier_service import VerifierService
from app.core.key_manager import key_manager


class ExportService:
    """Creates court-admissible, portable forensic zip packages."""

    @staticmethod
    def create_forensic_package(db: Session, investigation_id: str) -> io.BytesIO:
        """
        Build an in-memory ZIP package containing:
        - evidence/ : raw JSON artifacts
        - manifests/ : jocky-chain.json & evidence-manifest.json
        - signatures/ : chain_tip.sig
        - public_keys/ : jocky_public_key.pem
        - reports/ : verification_report.json
        - standalone_verifier.py : independent verification script
        """
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found.")

        # Ensure chain manifest is up to date
        manifest_obj = ChainService.update_chain_manifest(db, investigation_id)
        manifest_dict = ChainService.get_manifest_dict(db, investigation_id)
        verification_report = VerifierService.verify_investigation_chain(db, investigation_id)

        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id
        ).all()

        pub_info = key_manager.get_public_key_info(manifest_obj.key_id)

        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            prefix = f"forensic_package_{investigation_id}/"

            # 1. Evidence Files
            for art in artifacts:
                art_path = Path(art.file_path)
                if art_path.is_file():
                    arcname = f"{prefix}evidence/round_{art.round_number}/{art_path.name}"
                    zf.write(art_path, arcname=arcname)

            # 2. Manifests
            zf.writestr(
                f"{prefix}manifests/jocky-chain.json",
                json.dumps(manifest_dict, indent=2, default=str)
            )
            evidence_manifest = {
                "investigation_id": investigation_id,
                "case_id": inv.id,
                "exported_at": datetime.now(tz=timezone.utc).isoformat(),
                "artifact_count": len(artifacts),
                "artifacts": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "operation": a.operation,
                        "collector": a.collector,
                        "round_number": a.round_number,
                        "sha256": a.sha256,
                        "file_size_bytes": a.file_size_bytes,
                        "collected_at": a.collected_at.isoformat() if a.collected_at else None
                    }
                    for a in artifacts
                ]
            }
            zf.writestr(
                f"{prefix}manifests/evidence-manifest.json",
                json.dumps(evidence_manifest, indent=2, default=str)
            )

            # 3. Signatures
            if manifest_obj.signature_hex:
                zf.writestr(
                    f"{prefix}signatures/chain_tip.sig",
                    manifest_obj.signature_hex
                )

            # 4. Public Keys
            zf.writestr(
                f"{prefix}public_keys/jocky_public_key.pem",
                pub_info["public_key_pem"]
            )
            zf.writestr(
                f"{prefix}public_keys/key_info.json",
                json.dumps({
                    "key_id": pub_info["key_id"],
                    "algorithm": "Ed25519",
                    "public_key_hex": pub_info["public_key_hex"]
                }, indent=2)
            )

            # 5. Verification Report
            zf.writestr(
                f"{prefix}reports/verification_report.json",
                json.dumps(verification_report, indent=2, default=str)
            )

            # 6. Standalone Independent Verifier Script
            verifier_script_path = settings.BACKEND_DIR / "standalone_verifier.py"
            if verifier_script_path.is_file():
                zf.write(verifier_script_path, arcname=f"{prefix}standalone_verifier.py")

            # 7. README with instructions
            readme_content = f"""JOCKY FORENSIC EVIDENCE PACKAGE
Case ID: {inv.id}
Investigation ID: {investigation_id}
Exported: {datetime.now(tz=timezone.utc).isoformat()}
Records: {len(artifacts)}
Chain Tip: {manifest_obj.chain_tip}
Signer Key: {manifest_obj.key_id}

INDEPENDENT VERIFICATION INSTRUCTIONS:
1. Ensure Python 3.10+ and 'cryptography' are installed:
   pip install cryptography

2. Run the included standalone verifier:
   python standalone_verifier.py --package ./

The verifier will check evidence payloads, RFC 8785 metadata, hash chain continuity,
sequence ordering, and the Ed25519 chain tip digital signature.
"""
            zf.writestr(f"{prefix}README.txt", readme_content)

        zip_buffer.seek(0)
        return zip_buffer
