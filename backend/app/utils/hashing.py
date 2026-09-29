import hashlib
from pathlib import Path
from typing import Any
from app.core.canonical import (
    canonicalize_json,
    canonical_sha256,
    stream_file_sha256,
    compute_record_hash,
    GENESIS_HASH
)

def calculate_sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 hex digest for in-memory bytes."""
    return hashlib.sha256(data).hexdigest()

def calculate_file_sha256(file_path: Path | str) -> str:
    """Calculate SHA-256 hex digest for a file on disk using streaming."""
    return stream_file_sha256(file_path)

__all__ = [
    "calculate_sha256_bytes",
    "calculate_file_sha256",
    "stream_file_sha256",
    "canonicalize_json",
    "canonical_sha256",
    "compute_record_hash",
    "GENESIS_HASH"
]

