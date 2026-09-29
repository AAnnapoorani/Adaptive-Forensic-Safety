import sys
import json
import zipfile
import io
from pathlib import Path
from tempfile import TemporaryDirectory

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.core.database import SessionLocal, init_db
from app.models.machine import Machine
from app.models.investigation import Investigation
from app.models.evidence import EvidenceArtifact, ProvenanceRecord, EvidenceChainManifest
from app.core.canonical import (
    canonicalize_json,
    compute_sha256_bytes,
    compute_file_sha256,
    build_canonical_record,
    compute_record_hash,
    GENESIS_HASH
)
from app.core.key_manager import JockyKeyManager, key_manager
from app.services.chain_service import ChainService
from app.services.verifier_service import VerifierService
from app.services.export_service import ExportService
from app.services.evidence_service import EvidenceService
from standalone_verifier import StandaloneVerifier


def test_phase18_evidence_chain_ed25519():
    print("=" * 70)
    print("Testing Phase 18: Evidence Integrity 2.0 (Hash Chain + Ed25519)")
    print("=" * 70)

    init_db()
    db = SessionLocal()

    try:
        # ── Test 1: Canonicalization Determinism (RFC 8785) ───────────────────
        print("\n--- Test 1: RFC 8785 JSON Canonicalization Determinism ---")
        obj_a = {"z": 1, "a": "hello", "m": [3, 2, 1], "sub": {"b": True, "a": False}}
        obj_b = {"a": "hello", "sub": {"a": False, "b": True}, "m": [3, 2, 1], "z": 1}
        
        canon_a = canonicalize_json(obj_a)
        canon_b = canonicalize_json(obj_b)
        assert canon_a == canon_b, "Canonicalization must yield identical bytes regardless of key order"
        assert compute_sha256_bytes(canon_a) == compute_sha256_bytes(canon_b)
        print("[PASS] RFC 8785 canonicalization is strictly deterministic across dict orders.")

        # ── Test 2: Genesis Hash Anchor ───────────────────────────────────────
        print("\n--- Test 2: Genesis Hash Anchor Verification ---")
        expected_genesis = compute_sha256_bytes(b"JOCKY-EVIDENCE-CHAIN-GENESIS-V1")
        assert GENESIS_HASH == expected_genesis
        assert GENESIS_HASH == "254e580515def211ef9e9aab16afbb94485cde23739d204b2d975d534c5a1ba6"
        print(f"[PASS] GENESIS_HASH matches specification: {GENESIS_HASH[:20]}...")

        # ── Test 3: Ed25519 Key Generation, Signing, and Verification ───────────
        print("\n--- Test 3: Ed25519 Asymmetric Cryptographic Signing ---")
        with TemporaryDirectory() as tmp_keydir:
            test_km = JockyKeyManager(key_dir=Path(tmp_keydir))
            k_id = test_km.get_or_create_active_key(alias="Phase18 Test Key")
            assert k_id.startswith("JOCKY-KEY-")
            
            test_message = b"FORENSIC_INTEGRITY_CHAIN_TIP_DATA"
            sig_hex = test_km.sign_data(test_message, key_id=k_id)
            assert len(sig_hex) == 128  # 64 bytes = 128 hex chars
            
            is_valid = test_km.verify_signature(sig_hex, test_message, key_id=k_id)
            assert is_valid is True, "Valid signature must verify"
            
            # Tamper 1 bit in signature
            corrupt_sig = "00" + sig_hex[2:]
            assert test_km.verify_signature(corrupt_sig, test_message, key_id=k_id) is False
            print("[PASS] Ed25519 key generation, 64-byte signing, and verification verified.")

        # ── Test 4: Key Rotation with Backward Verification ───────────────────
        print("\n--- Test 4: Ed25519 Key Rotation with Historical Preservation ---")
        with TemporaryDirectory() as tmp_keydir:
            rot_km = JockyKeyManager(key_dir=Path(tmp_keydir))
            k1_id = rot_km.get_or_create_active_key(alias="Key 1")
            sig1 = rot_km.sign_data(b"MSG1", key_id=k1_id)
            
            k2_id = rot_km.rotate_key(alias="Key 2")
            assert k2_id != k1_id
            assert rot_km.get_or_create_active_key() == k2_id
            
            # Historical signature must still verify using key 1
            assert rot_km.verify_signature(sig1, b"MSG1", key_id=k1_id) is True
            # New message signed with key 2
            sig2 = rot_km.sign_data(b"MSG2", key_id=k2_id)
            assert rot_km.verify_signature(sig2, b"MSG2", key_id=k2_id) is True
            print("[PASS] Historical signatures verify after key rotation.")

        # ── Test 5: Setup Test Investigation and Chain Construction ────────────
        print("\n--- Test 5: Sequential Hash Chain Construction (3 Artifacts) ---")
        machine = db.query(Machine).first()
        if not machine:
            machine = Machine(id="M-P18", hostname="p18-host", os_name="Windows", status="ACTIVE")
            db.add(machine)
            db.commit()

        inv_id = "INV-P18-INTEGRITY"
        inv = Investigation(
            id=inv_id,
            intent="evidence_chain_test",
            machine_id=machine.id,
            status="IN_PROGRESS"
        )
        db.merge(inv)
        db.commit()

        # Clean prior test records if any
        db.query(ProvenanceRecord).filter(ProvenanceRecord.investigation_id == inv_id).delete()
        db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == inv_id).delete()
        db.query(EvidenceChainManifest).filter(EvidenceChainManifest.investigation_id == inv_id).delete()
        db.commit()

        # Add 3 evidence artifacts
        m_id = str(machine.id)
        art1 = EvidenceService.save_evidence(
            db, inv_id, 1, "PROCESS.LIST", "Process Collector",
            {"procs": ["svchost.exe", "explorer.exe"]}, "Triage processes", m_id
        )
        art2 = EvidenceService.save_evidence(
            db, inv_id, 1, "NETSTAT.ACTIVE", "Net Collector",
            {"conns": ["127.0.0.1:443", "10.0.0.1:8080"]}, "Network triage", m_id
        )
        art3 = EvidenceService.save_evidence(
            db, inv_id, 2, "REGISTRY.PERSISTENCE", "Registry Collector",
            {"run_keys": ["Software\\Run"]}, "Persistence checks", m_id
        )

        chain_records = ChainService.get_chain_records(db, inv_id)
        assert len(chain_records) == 3, f"Expected 3 records, got {len(chain_records)}"

        # Check sequence numbers and hash linking
        r1, r2, r3 = chain_records[0], chain_records[1], chain_records[2]
        
        assert r1["sequence_number"] == 1
        assert r1["previous_record_hash"] == GENESIS_HASH
        assert len(r1["record_hash"]) == 64

        assert r2["sequence_number"] == 2
        assert r2["previous_record_hash"] == r1["record_hash"]
        assert len(r2["record_hash"]) == 64

        assert r3["sequence_number"] == 3
        assert r3["previous_record_hash"] == r2["record_hash"]
        assert len(r3["record_hash"]) == 64
        print(f"[PASS] Hash chain successfully linked: Genesis ➔ #{r1['sequence_number']} ➔ #{r2['sequence_number']} ➔ #{r3['sequence_number']}")

        # ── Test 6: Chain Tip Manifest & Ed25519 Signing ───────────────────────
        print("\n--- Test 6: Chain Tip Assembly and Digital Manifest Signing ---")
        manifest = ChainService.update_chain_manifest(db, inv_id)
        assert manifest is not None
        assert manifest.record_count == 3
        assert manifest.chain_tip == r3["record_hash"]
        assert len(manifest.signature_hex) == 128
        assert manifest.key_id is not None
        print(f"[PASS] Chain manifest sealed. Tip={manifest.chain_tip[:16]}..., Key={manifest.key_id}")

        # ── Test 7: Pristine Chain Verification (All 7 Passes) ────────────────
        print("\n--- Test 7: 7-Pass Verification on Pristine Chain ---")
        report = VerifierService.verify_investigation_chain(db, inv_id)
        assert report["result"] == "VERIFIED"
        assert report["verified"] is True
        assert report["records_count"] == 3
        for k, v in report["diagnostics"].items():
            assert v == "PASSED", f"Expected diagnostic {k} to be PASSED, got {v}"
        print("[PASS] Pristine chain passed all 7 forensic verification checks.")

        # ── Test 8: Tamper Vector 1 — Modified Evidence Payload Byte ──────────
        print("\n--- Test 8: Tamper Attack Vector 1 (Modified Payload Byte) ---")
        art1_file = Path(str(art1.file_path))
        orig_art1_content = art1_file.read_bytes()
        
        # Tamper 1 byte in the file
        with open(art1_file, "ab") as f:
            f.write(b"X")

        tamper_report_1 = VerifierService.verify_investigation_chain(db, inv_id)
        assert tamper_report_1["result"] == "TAMPERED"
        assert tamper_report_1["verified"] is False
        assert tamper_report_1["diagnostics"]["evidence_hashes"] == "FAILED"
        assert tamper_report_1["failure_details"]["attack_type"] == "MODIFIED_EVIDENCE_PAYLOAD"
        print(f"[PASS] Caught payload tamper in Pass 1: {tamper_report_1['failure_details']['reason'][:80]}...")

        # Restore original content
        art1_file.write_bytes(orig_art1_content)
        assert VerifierService.verify_investigation_chain(db, inv_id)["result"] == "VERIFIED"

        # ── Test 9: Tamper Vector 2 — Provenance Metadata Manipulation ────────
        print("\n--- Test 9: Tamper Attack Vector 2 (Modified Provenance Metadata) ---")
        p2 = db.query(ProvenanceRecord).filter(ProvenanceRecord.artifact_id == art2.id).first()
        assert p2 is not None
        orig_reason = str(getattr(p2, "reason", "") or "")
        setattr(p2, "reason", "FORGED INVESTIGATOR RATIONALE")
        db.commit()

        tamper_report_2 = VerifierService.verify_investigation_chain(db, inv_id)
        assert tamper_report_2["result"] == "TAMPERED"
        assert tamper_report_2["diagnostics"]["metadata_integrity"] == "FAILED"
        assert tamper_report_2["failure_details"]["attack_type"] == "CANONICAL_METADATA_TAMPERED"
        print(f"[PASS] Caught metadata tamper in Pass 2: {tamper_report_2['failure_details']['reason'][:80]}...")

        # Restore metadata
        setattr(p2, "reason", orig_reason)
        db.commit()
        assert VerifierService.verify_investigation_chain(db, inv_id)["result"] == "VERIFIED"

        # ── Test 10: Tamper Vector 3 — Broken Hash Chain Link Pointer ─────────
        print("\n--- Test 10: Tamper Attack Vector 3 (Corrupted Previous Hash) ---")
        p3 = db.query(ProvenanceRecord).filter(ProvenanceRecord.artifact_id == art3.id).first()
        assert p3 is not None
        orig_prev = str(getattr(p3, "previous_record_hash", "") or "")
        setattr(p3, "previous_record_hash", "0" * 64)
        db.commit()

        tamper_report_3 = VerifierService.verify_investigation_chain(db, inv_id)
        assert tamper_report_3["result"] == "TAMPERED"
        assert tamper_report_3["diagnostics"]["hash_chain"] == "FAILED"
        assert tamper_report_3["failure_details"]["attack_type"] == "PREVIOUS_HASH_MISMATCH"
        print(f"[PASS] Caught broken hash chain link in Pass 3: {tamper_report_3['failure_details']['reason'][:80]}...")

        # Restore pointer
        setattr(p3, "previous_record_hash", orig_prev)
        db.commit()
        assert VerifierService.verify_investigation_chain(db, inv_id)["result"] == "VERIFIED"

        # ── Test 11: Tamper Vector 4 — Intermediate Record Deletion ───────────
        print("\n--- Test 11: Tamper Attack Vector 4 (Deleted Intermediate Record) ---")
        # Temporarily change sequence number of record 3 from 3 to 4, leaving gap at 3
        setattr(p3, "sequence_number", 4)
        db.commit()

        tamper_report_4 = VerifierService.verify_investigation_chain(db, inv_id)
        assert tamper_report_4["result"] == "TAMPERED"
        assert tamper_report_4["diagnostics"]["chain_ordering"] == "FAILED"
        assert tamper_report_4["failure_details"]["attack_type"] == "SEQUENCE_GAP_OR_OUT_OF_ORDER"
        print(f"[PASS] Caught sequence gap in Pass 4: {tamper_report_4['failure_details']['reason'][:80]}...")

        setattr(p3, "sequence_number", 3)
        db.commit()
        assert VerifierService.verify_investigation_chain(db, inv_id)["result"] == "VERIFIED"

        # ── Test 12: Tamper Vector 5 — Forged Ed25519 Signature / Tip ──────────
        print("\n--- Test 12: Tamper Attack Vector 5 (Ed25519 Signature Forgery) ---")
        m_rec = db.query(EvidenceChainManifest).filter(EvidenceChainManifest.investigation_id == inv_id).first()
        assert m_rec is not None
        orig_sig = str(getattr(m_rec, "signature_hex", "") or "")
        setattr(m_rec, "signature_hex", "00" * 64)
        db.commit()

        tamper_report_5 = VerifierService.verify_investigation_chain(db, inv_id)
        assert tamper_report_5["result"] == "TAMPERED"
        assert tamper_report_5["diagnostics"]["ed25519_signature"] == "FAILED"
        assert tamper_report_5["failure_details"]["attack_type"] == "INVALID_ED25519_SIGNATURE"
        print(f"[PASS] Caught forged signature in Pass 6: {tamper_report_5['failure_details']['reason'][:80]}...")

        setattr(m_rec, "signature_hex", orig_sig)
        db.commit()
        assert VerifierService.verify_investigation_chain(db, inv_id)["result"] == "VERIFIED"

        # ── Test 13: Exported Forensic Package (.zip) & Standalone CLI ────────
        print("\n--- Test 13: Exported Zip Archive & Standalone Offline CLI Verifier ---")
        zip_buf = ExportService.create_forensic_package(db, inv_id)
        assert len(zip_buf.getvalue()) > 1000
        
        # Test standalone verifier directly on this zip
        standalone_res = StandaloneVerifier.verify_package(zip_buf.getvalue())
        assert standalone_res["result"] == "VERIFIED"
        assert standalone_res["verified"] is True
        assert standalone_res["records_count"] == 3
        print(f"[PASS] Standalone offline verifier verified exported package: {standalone_res['result']}")

        # Test standalone verifier detects 1-byte tamper in zipped artifact
        with zipfile.ZipFile(zip_buf, "r") as zf:
            namelist = zf.namelist()
            evidence_file = next(n for n in namelist if "evidence/" in n and n.endswith(".json"))
            orig_data = zf.read(evidence_file)
            
            # Rebuild a tampered zip
            tampered_zip_buf = io.BytesIO()
            with zipfile.ZipFile(tampered_zip_buf, "w") as z_out:
                for item in zf.infolist():
                    data = zf.read(item.filename)
                    if item.filename == evidence_file:
                        data += b" " # 1 byte whitespace tamper
                    z_out.writestr(item, data)

        tampered_cli_res = StandaloneVerifier.verify_package(tampered_zip_buf.getvalue())
        assert tampered_cli_res["result"] == "TAMPERED"
        assert tampered_cli_res["verified"] is False
        assert tampered_cli_res["diagnostics"]["evidence_hashes"] == "FAILED"
        print(f"[PASS] Standalone CLI caught zip tampering: {tampered_cli_res['failure_details']['reason'][:80]}...")

        # ── Test 14: Backward Compatibility with Legacy Unchained Evidence ────
        print("\n--- Test 14: Backward Compatibility with Legacy Evidence ---")
        legacy_inv_id = "INV-LEGACY-001"
        legacy_inv = Investigation(id=legacy_inv_id, intent="legacy_test", machine_id=machine.id, status="COMPLETED")
        db.merge(legacy_inv)
        db.query(ProvenanceRecord).filter(ProvenanceRecord.investigation_id == legacy_inv_id).delete()
        db.commit()

        # Add unchained record
        leg_rec = ProvenanceRecord(
            id="PROV-LEG-1",
            investigation_id=legacy_inv_id,
            artifact_id="EV-LEG-1",
            intent="legacy",
            collector="Legacy Collector",
            operation="LEGACY.COLLECT",
            machine_id=machine.id,
            round_number=1,
            reason="Legacy collect",
            sha256="abc" * 21 + "a",
            sequence_number=None,
            previous_record_hash=None,
            record_hash=None
        )
        db.add(leg_rec)
        db.commit()

        leg_report = VerifierService.verify_investigation_chain(db, legacy_inv_id)
        assert leg_report["result"] == "LEGACY_FORMAT"
        assert leg_report["is_legacy"] is True
        assert leg_report["verified"] is False
        print("[PASS] Legacy unchained evidence gracefully reported as LEGACY_FORMAT without errors.")

        print("\n" + "=" * 70)
        print(">>> ALL 14 PHASE 18 EVIDENCE INTEGRITY 2.0 TESTS PASSED! <<<")
        print("=" * 70)

    finally:
        db.close()


if __name__ == "__main__":
    test_phase18_evidence_chain_ed25519()
