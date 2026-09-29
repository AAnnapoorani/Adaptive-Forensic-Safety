"""
JOCKY Forensic Evidence Integrity 2.0 — Canonicalization & Cryptographic Hasher
Implements RFC 8785 (JSON Canonicalization Scheme - JCS) and streaming SHA-256
to guarantee deterministic hashing across diverse runtime platforms and architectures.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Deterministic Genesis Hash for JOCKY Evidence Hash Chain
GENESIS_HASH = hashlib.sha256(b"JOCKY-EVIDENCE-CHAIN-GENESIS-V1").hexdigest()


def _normalize_obj_for_canonical(obj: Any) -> Any:
    """Recursively normalize objects to JSON-serializable primitives for RFC 8785 compliance."""
    if isinstance(obj, dict):
        return {str(k): _normalize_obj_for_canonical(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_obj_for_canonical(item) for item in obj]
    elif isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        else:
            obj = obj.astimezone(timezone.utc)
        iso = obj.isoformat()
        if iso.endswith("+00:00"):
            iso = iso[:-6] + "Z"
        elif not iso.endswith("Z"):
            iso = iso + "Z"
        return iso
    elif isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    elif isinstance(obj, Path):
        return obj.as_posix()
    elif isinstance(obj, (int, bool)) or obj is None:
        return obj
    elif isinstance(obj, float):
        if obj.is_integer():
            return int(obj)
        return obj
    else:
        return str(obj)


def canonicalize_json(data: Any) -> bytes:
    """
    Produce canonical UTF-8 bytes for any Python structure conforming to RFC 8785:
    - Keys sorted lexicographically
    - No insignificant whitespace (',' and ':')
    - Deterministic character escaping
    """
    normalized = _normalize_obj_for_canonical(data)
    json_str = json.dumps(
        normalized,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )
    return json_str.encode("utf-8")


def canonical_sha256(data: Any) -> str:
    """Calculate SHA-256 digest of canonically serialized data."""
    return hashlib.sha256(canonicalize_json(data)).hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 digest directly from bytes."""
    return hashlib.sha256(data).hexdigest()


def stream_file_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """
    Streaming SHA-256 calculation for arbitrary size on-disk evidence files.
    Avoids loading full files into memory, supporting multi-GB forensic captures.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Forensic artifact file not found: {file_path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


compute_file_sha256 = stream_file_sha256


def build_canonical_record(
    artifact_id: str,
    case_id: str,
    collection_id: str,
    timestamp_utc: str,
    collector: str,
    host_id: str,
    operation: str,
    source: str,
    artifact_type: str,
    file_path: str,
    size: int,
    sha256: str,
    previous_record_hash: str,
    sequence_number: int,
    round_number: int,
    reason: str = "",
    key_id: str = "",
    jocky_script: str = "",
    encryption_algorithm: str = "NONE",
    encryption_key_id: str = "",
    record_hash: str = "",
    signature: str = ""
) -> dict[str, Any]:
    """
    Constructs the canonical metadata dictionary conforming to JOCKY Evidence Integrity 2.0 specification.
    """
    return {
        "artifact_type": artifact_type,
        "case_id": case_id,
        "collection_id": collection_id,
        "collector": collector,
        "encryption": {
            "algorithm": encryption_algorithm,
            "key_id": encryption_key_id
        },
        "evidence_id": artifact_id,
        "file_path": Path(file_path).as_posix(),
        "host_id": host_id,
        "jocky_script": jocky_script or "",
        "key_id": key_id or "",
        "operation": operation,
        "previous_record_hash": previous_record_hash,
        "reason": reason or "",
        "record_hash": record_hash or "",
        "round_number": round_number,
        "sequence_number": sequence_number,
        "sha256": sha256,
        "signature": signature or "",
        "size": size,
        "source": source,
        "timestamp_utc": timestamp_utc
    }


def compute_record_hash(record_metadata: dict[str, Any], previous_hash: str) -> str:
    """
    Compute cryptographic hash of an evidence record in the hash chain:
    RecordHash = SHA256(Canonical(record_without_hash_and_sig) + previous_hash.encode())
    
    Guarantees tamper-evident linking: changing any field in record_metadata or
    in the previous hash breaks all subsequent hashes in the chain.
    """
    filtered = {
        k: v for k, v in record_metadata.items()
        if k not in ("record_hash", "signature", "signature_hex", "current_hash")
    }
    filtered["previous_record_hash"] = previous_hash

    canonical_bytes = canonicalize_json(filtered)
    combined = canonical_bytes + previous_hash.encode("utf-8")
    return hashlib.sha256(combined).hexdigest()
