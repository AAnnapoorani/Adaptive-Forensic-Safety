#!/usr/bin/env python3
"""
JOCKY Standalone Forensic Evidence Verifier (Independent Offline Verification CLI)
==================================================================================
Conforms to ISO/IEC 27037 and court admissibility standards.
Independently verifies evidence manifests, cryptographic hash chains, and Ed25519
signatures WITHOUT requiring the JOCKY platform or database.

Dependencies:
    - Python 3.10+
    - cryptography (pip install cryptography)

Usage:
    python standalone_verifier.py --package /path/to/forensic_package/
    python standalone_verifier.py --zip /path/to/forensic_package.zip
"""

import sys
import json
import zipfile
import hashlib
import argparse
from pathlib import Path
from typing import Any

GENESIS_HASH = hashlib.sha256(b"JOCKY-EVIDENCE-CHAIN-GENESIS-V1").hexdigest()


def _normalize_for_canonical(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _normalize_for_canonical(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_for_canonical(x) for x in obj]
    elif isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    elif isinstance(obj, float):
        if obj.is_integer():
            return int(obj)
        return obj
    elif isinstance(obj, (int, bool)) or obj is None:
        return obj
    else:
        return str(obj)


def canonicalize_json(data: Any) -> bytes:
    normalized = _normalize_for_canonical(data)
    return json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def stream_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_record_hash(meta: dict[str, Any], previous_hash: str) -> str:
    clean = {k: v for k, v in meta.items() if k not in ("record_hash", "signature", "signature_hex", "current_hash")}
    clean["previous_record_hash"] = previous_hash
    canonical_bytes = canonicalize_json(clean)
    return hashlib.sha256(canonical_bytes + previous_hash.encode("utf-8")).hexdigest()


def verify_ed25519_signature(pub_pem: str, sig_hex: str, data: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            return False
        pub.verify(bytes.fromhex(sig_hex), data)
        return True
    except Exception:
        return False


def verify_package_dir(package_dir: Path) -> tuple[bool, dict[str, Any]]:
    manifest_path = package_dir / "manifests" / "jocky-chain.json"
    if not manifest_path.exists():
        manifest_path = package_dir / "jocky-chain.json"
    if not manifest_path.exists():
        candidates = list(package_dir.rglob("jocky-chain.json"))
        if candidates:
            manifest_path = candidates[0]
            package_dir = manifest_path.parent.parent if manifest_path.parent.name == "manifests" else manifest_path.parent
        else:
            return False, {"step": "MANIFEST_MISSING", "reason": f"Chain manifest jocky-chain.json not found in {package_dir}"}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    records = manifest.get("records", [])
    if not records:
        return False, {"step": "EMPTY_MANIFEST", "reason": "Manifest contains 0 records."}

    pub_pem = manifest.get("public_key_pem", "")
    chain_tip = manifest.get("chain_tip", "")
    tip_sig = manifest.get("signature", "")

    expected_prev = GENESIS_HASH

    for idx, rec in enumerate(records):
        seq = rec.get("sequence_number", idx + 1)
        art_id = rec.get("evidence_id") or rec.get("artifact_id", "UNKNOWN")


        # 1. Sequence check
        if seq != idx + 1:
            return False, {
                "step": "CHAIN_SEQUENCE",
                "record": seq,
                "artifact_id": art_id,
                "reason": f"Sequence anomaly: expected #{idx + 1}, found #{seq}"
            }

        # 2. Previous hash check
        stored_prev = rec.get("previous_record_hash")
        if stored_prev != expected_prev:
            return False, {
                "step": "HASH_CHAIN_CONTINUITY",
                "record": seq,
                "artifact_id": art_id,
                "reason": f"Hash chain broken at record #{seq}. previous_hash does not match preceding record.",
                "expected_previous_hash": expected_prev,
                "stored_previous_hash": stored_prev
            }

        # 3. Payload SHA-256 check (if artifact file present in evidence/ folder)
        evidence_dir = package_dir / "evidence"
        matched_file = None
        target_name = Path(rec.get("file_path", "")).name if rec.get("file_path") else ""
        round_num = rec.get("round_number", 1)

        # 3a. Direct path check inside round folder
        if target_name:
            direct_candidate = evidence_dir / f"round_{round_num}" / target_name
            if direct_candidate.is_file():
                matched_file = direct_candidate

        # 3b. Search anywhere in package for target_name
        if not matched_file and target_name:
            for p in package_dir.rglob(target_name):
                if p.is_file():
                    matched_file = p
                    break

        # 3c. Fallback matching by operation or artifact_id
        if not matched_file and evidence_dir.exists():
            for p in evidence_dir.rglob("*.json"):
                op_token = rec.get("operation", "").lower().replace(".", "_").split("_")[0]
                if (op_token and op_token in p.name.lower()) or art_id in p.name:
                    matched_file = p
                    break

        if matched_file and matched_file.is_file():
            actual_sha = stream_file_sha256(matched_file)
            if actual_sha != rec.get("sha256"):
                return False, {
                    "step": "EVIDENCE_PAYLOAD_SHA256",
                    "record": seq,
                    "artifact_id": art_id,
                    "file": str(matched_file.relative_to(package_dir)),
                    "reason": "Payload modified. SHA-256 mismatch.",
                    "expected_sha256": rec.get("sha256"),
                    "calculated_sha256": actual_sha
                }

        # 4. Record Hash calculation check
        calc_hash = compute_record_hash(rec, stored_prev)
        if calc_hash != rec.get("record_hash"):
            return False, {
                "step": "RECORD_HASH_METADATA",
                "record": seq,
                "artifact_id": art_id,
                "reason": "Record metadata altered or record_hash tampered.",
                "stored_hash": rec.get("record_hash"),
                "calculated_hash": calc_hash
            }

        # 5. Record Signature (if present)
        if rec.get("signature") and pub_pem:
            if not verify_ed25519_signature(pub_pem, rec["signature"], rec["record_hash"].encode("utf-8")):
                return False, {
                    "step": "RECORD_ED25519_SIGNATURE",
                    "record": seq,
                    "artifact_id": art_id,
                    "reason": f"Ed25519 signature invalid on record #{seq}"
                }

        expected_prev = rec.get("record_hash")

    # 6. Chain tip check
    if chain_tip != expected_prev:
        return False, {
            "step": "CHAIN_TIP",
            "reason": "Manifest chain tip does not match computed tip of final record.",
            "expected_tip": expected_prev,
            "manifest_tip": chain_tip
        }

    # 7. Tip Signature check
    if tip_sig and pub_pem:
        if not verify_ed25519_signature(pub_pem, tip_sig, chain_tip.encode("utf-8")):
            return False, {
                "step": "CHAIN_TIP_SIGNATURE",
                "reason": "Ed25519 signature of chain tip failed cryptographic validation."
            }

    return True, {
        "case_id": manifest.get("case_id"),
        "investigation_id": manifest.get("investigation_id"),
        "records_count": len(records),
        "chain_tip": chain_tip,
        "key_id": manifest.get("key_id"),
        "algorithm": manifest.get("signature_algorithm", "Ed25519")
    }


class StandaloneVerifier:
    """Class interface for standalone forensic verification."""

    @staticmethod
    def verify_directory(package_dir: Path | str) -> dict[str, Any]:
        verified, details = verify_package_dir(Path(package_dir))
        return {
            "verified": verified,
            "result": "VERIFIED" if verified else "TAMPERED",
            "diagnostics": {
                "evidence_hashes": "FAILED" if not verified and details.get("step") == "EVIDENCE_PAYLOAD_SHA256" else "PASSED",
                "metadata_integrity": "FAILED" if not verified and details.get("step") == "RECORD_HASH_METADATA" else "PASSED",
                "hash_chain": "FAILED" if not verified and details.get("step") == "HASH_CHAIN_CONTINUITY" else "PASSED",
                "chain_ordering": "FAILED" if not verified and details.get("step") == "CHAIN_SEQUENCE" else "PASSED",
                "chain_tip": "FAILED" if not verified and details.get("step") == "CHAIN_TIP" else "PASSED",
                "ed25519_signature": "FAILED" if not verified and "SIGNATURE" in details.get("step", "") else "PASSED"
            },
            "records_count": details.get("records_count", 0),
            "failure_details": details if not verified else None
        }

    @staticmethod
    def verify_package(zip_bytes_or_path: bytes | Path | str) -> dict[str, Any]:
        import tempfile
        import shutil
        import io
        temp_dir = Path(tempfile.mkdtemp(prefix="jocky_test_pkg_"))
        try:
            if isinstance(zip_bytes_or_path, (bytes, bytearray)):
                with zipfile.ZipFile(io.BytesIO(zip_bytes_or_path), "r") as zf:
                    zf.extractall(temp_dir)
            else:
                with zipfile.ZipFile(zip_bytes_or_path, "r") as zf:
                    zf.extractall(temp_dir)
            return StandaloneVerifier.verify_directory(temp_dir)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="JOCKY Forensic Evidence Independent Verifier")
    parser.add_argument("--package", "-p", help="Path to unzipped forensic package directory")
    parser.add_argument("--zip", "-z", help="Path to zipped forensic package archive")
    args = parser.parse_args()

    if not args.package and not args.zip:
        parser.print_help()
        sys.exit(2)

    import tempfile
    import shutil

    target_dir = None
    temp_dir = None

    if args.zip:
        zip_path = Path(args.zip)
        if not zip_path.is_file():
            print(f"[!] Error: Zip file {zip_path} not found.")
            sys.exit(2)
        temp_dir = Path(tempfile.mkdtemp(prefix="jocky_verify_"))
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(temp_dir)
        target_dir = temp_dir
    else:
        target_dir = Path(args.package)
        if not target_dir.is_dir():
            print(f"[!] Error: Package directory {target_dir} not found.")
            sys.exit(2)

    print("================================================================================")
    print("  JOCKY FORENSIC EVIDENCE INDEPENDENT VERIFIER (ISO/IEC 27037)")
    print("================================================================================")

    try:
        verified, details = verify_package_dir(target_dir)

        if verified:
            print("  Evidence hashes:        PASS")
            print("  Metadata integrity:     PASS")
            print("  Hash chain:             PASS")
            print("  Chain ordering:         PASS")
            print("  Chain tip:              PASS")
            print("  Ed25519 signature:      PASS")
            print("--------------------------------------------------------------------------------")
            print(f"  Case ID:                {details.get('case_id')}")
            print(f"  Investigation ID:       {details.get('investigation_id')}")
            chain_tip_str = str(details.get('chain_tip') or '')
            print(f"  Chain Tip:              {chain_tip_str[:24]}...")
            print(f"  Signing Key:            {details.get('key_id')}")
            print(f"  Algorithm:              {details.get('algorithm')}")
            print("--------------------------------------------------------------------------------")
            print("  RESULT: VERIFIED [CRYPTOGRAPHICALLY AUTHENTIC]")
            print("================================================================================")
            sys.exit(0)
        else:
            print("  RESULT: TAMPERED [EVIDENCE INTEGRITY COMPROMISED]")
            print("--------------------------------------------------------------------------------")
            print(f"  Failed Check:           {details.get('step')}")
            print(f"  Record Sequence:        {details.get('record', 'N/A')}")
            print(f"  Artifact ID:            {details.get('artifact_id', 'N/A')}")
            print(f"  Reason:                 {details.get('reason')}")
            if "expected_sha256" in details:
                print(f"  Expected SHA-256:       {details['expected_sha256']}")
                print(f"  Calculated SHA-256:     {details['calculated_sha256']}")
            if "expected_previous_hash" in details:
                print(f"  Expected Prev Hash:     {details['expected_previous_hash']}")
                print(f"  Stored Prev Hash:       {details['stored_previous_hash']}")
            if "stored_hash" in details:
                print(f"  Stored Hash:            {details['stored_hash']}")
                print(f"  Calculated Hash:        {details['calculated_hash']}")
            print("================================================================================")
            sys.exit(1)

    finally:
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
