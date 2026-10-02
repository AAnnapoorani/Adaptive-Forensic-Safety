import hashlib
import platform
import socket
import sys
from pathlib import Path

# Add project root to sys.path so agent.identity can be imported
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

def get_machine_info() -> dict:
    """Retrieve local system details safely using the unified hardware-bound identity."""
    try:
        from agent.identity import get_or_create_identity
        ident = get_or_create_identity()
        machine_id = ident.machine_id
        hostname = ident.hostname
        os_name = ident.os_name
        os_version = ident.os_version
        architecture = ident.architecture
        os_type = ident.os_type
        mac_address = ident.mac_address
    except Exception:
        hostname = socket.gethostname() if hasattr(socket, "gethostname") else "unknown-host"
        h_digest = hashlib.sha256(hostname.encode("utf-8", errors="ignore")).hexdigest()[:12].upper()
        machine_id = f"JOCKY-{h_digest}"
        os_name = platform.system()
        os_version = platform.version() or platform.release()
        architecture = platform.machine()
        os_type = platform.system()
        mac_address = None

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "127.0.0.1"

    return {
        "id": machine_id,
        "machine_id": machine_id,
        "hostname": hostname,
        "os_type": os_type,
        "os_name": os_name,
        "os_version": os_version,
        "architecture": architecture,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "status": "ACTIVE"
    }

