import hashlib
import platform
import socket
import uuid

def get_machine_info() -> dict:
    """Retrieve local system details safely."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown-host"

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "127.0.0.1"

    # Truly deterministic machine ID based on SHA-256 of hostname (stable across process restarts)
    h_digest = hashlib.sha256(hostname.encode("utf-8", errors="ignore")).hexdigest()[:8]
    machine_id = f"MACHINE-{int(h_digest, 16) % 100000:05d}"

    return {
        "id": machine_id,
        "hostname": hostname,
        "os_name": platform.system(),
        "os_version": platform.version() or platform.release(),
        "architecture": platform.machine(),
        "ip_address": ip_address,
        "status": "ACTIVE"
    }
