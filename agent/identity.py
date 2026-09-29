"""
JOCKY Agent — Hardware-Bound Persistent Machine Identity Manager

Generates and persists a stable, tamper-resistant machine identity on the physical host.
The identity survives:
  - Application & browser restarts
  - Multiple logins / logouts
  - IP address, Wi-Fi, Ethernet, and DHCP changes
  - VPN connects/disconnects
  - Backend server restarts

Storage locations:
  - Windows: %APPDATA%/JOCKY/machine_id.json (fallback: ~/.jocky/machine_id.json)
  - Linux:   /etc/jocky/machine_id.json (fallback: ~/.jocky/machine_id.json)
"""

import os
import sys
import json
import uuid
import socket
import hashlib
import platform
import subprocess
from pathlib import Path


def _get_storage_path() -> Path:
    """Determine the persistent OS storage path for machine identity."""
    if platform.system() == "Windows":
        app_data = os.environ.get("APPDATA")
        if app_data:
            base_dir = Path(app_data) / "JOCKY"
        else:
            base_dir = Path.home() / ".jocky"
    else:
        # Linux / Unix
        if os.path.exists("/etc") and os.access("/etc", os.W_OK):
            base_dir = Path("/etc/jocky")
        else:
            base_dir = Path.home() / ".jocky"

    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "machine_id.json"


def _get_hardware_seed() -> str:
    """
    Collect immutable physical machine hardware properties to seed
    the deterministic cryptographic machine identifier.
    """
    seeds = []

    # 1. Primary MAC address
    try:
        raw_mac = uuid.getnode()
        seeds.append(f"mac:{raw_mac}")
    except Exception:
        pass

    # 2. Hostname
    try:
        seeds.append(f"host:{socket.gethostname().lower().strip()}")
    except Exception:
        pass

    # 3. OS-Specific Immutable Hardware GUID
    system = platform.system()
    if system == "Windows":
        # Check Windows MachineGuid in Registry
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if guid:
                    seeds.append(f"win_guid:{guid.strip()}")
        except Exception:
            # Fallback to WMIC BIOS UUID
            try:
                out = subprocess.check_output(
                    ["wmic", "csproduct", "get", "uuid"],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                lines = [l.strip() for l in out.splitlines() if l.strip() and "UUID" not in l]
                if lines:
                    seeds.append(f"wmic_uuid:{lines[0]}")
            except Exception:
                pass

    elif system == "Linux":
        # Check /etc/machine-id or /var/lib/dbus/machine-id
        for mid_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                p = Path(mid_path)
                if p.exists():
                    mid = p.read_text().strip()
                    if mid:
                        seeds.append(f"linux_mid:{mid}")
                        break
            except Exception:
                pass

    # 4. Processor / Architecture
    seeds.append(f"arch:{platform.machine()}")
    seeds.append(f"proc:{platform.processor()}")

    return "|".join(seeds)


def _detect_os_details() -> dict:
    """Accurately detect OS type, distribution, and exact version."""
    system = platform.system()
    arch = platform.machine() or "x86_64"

    if system == "Windows":
        win_ver = platform.win32_ver()
        # platform.win32_ver() -> (release, version, csd, ptype)
        rel = win_ver[0] or "10"
        build = win_ver[1] or ""
        os_version = f"Windows {rel} (Build {build})".strip()
        os_type = "Windows"
        os_name = f"Windows {rel}"
    elif system == "Linux":
        os_type = "Linux"
        try:
            # Python 3.10+ freedesktop os-release
            info = platform.freedesktop_os_release()
            os_name = info.get("NAME", "Linux")
            os_version = info.get("PRETTY_NAME", f"{os_name} {platform.release()}")
        except Exception:
            os_name = "Linux"
            os_version = f"Linux {platform.release()}"
    elif system == "Darwin":
        os_type = "macOS"
        os_name = "macOS"
        mac_ver = platform.mac_ver()[0]
        os_version = f"macOS {mac_ver}" if mac_ver else "macOS"
    else:
        os_type = system
        os_name = system
        os_version = platform.release()

    return {
        "os_type": os_type,
        "os_name": os_name,
        "os_version": os_version,
        "architecture": arch
    }


class MachineIdentity:
    """Represents the persistent identity of this physical machine."""

    def __init__(self, machine_id: str, hostname: str, os_type: str, os_name: str,
                 os_version: str, architecture: str, mac_address: str):
        self.machine_id = machine_id
        self.hostname = hostname
        self.os_type = os_type
        self.os_name = os_name
        self.os_version = os_version
        self.architecture = architecture
        self.mac_address = mac_address

    def to_dict(self) -> dict:
        return {
            "machine_id": self.machine_id,
            "hostname": self.hostname,
            "os_type": self.os_type,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "mac_address": self.mac_address
        }


def get_or_create_identity(force_reset: bool = False, mock_os: str | None = None, mock_hostname: str | None = None) -> MachineIdentity:
    """
    Get the existing machine identity from storage, or generate and persist
    a deterministic identity if none exists.
    Supports mock_os (e.g. 'linux') for testing Linux hosts without physical Linux hardware.
    """
    if mock_os:
        mock_os_lower = mock_os.lower()
        if "linux" in mock_os_lower:
            m_type = "Linux"
            m_name = "Ubuntu 22.04 LTS"
            m_ver = "6.5.0-35-generic"
        elif "win" in mock_os_lower:
            m_type = "Windows"
            m_name = "Windows 11 Pro"
            m_ver = "10.0.22631"
        else:
            m_type = mock_os.capitalize()
            m_name = mock_os
            m_ver = "1.0.0"

        m_host = mock_hostname or f"UBUNTU-SRV-01"
        seed = f"mock:{m_type}:{m_host}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
        return MachineIdentity(
            machine_id=f"JOCKY-{digest}",
            hostname=m_host,
            os_type=m_type,
            os_name=m_name,
            os_version=m_ver,
            architecture="x86_64",
            mac_address="02:42:ac:11:00:02"
        )

    filepath = _get_storage_path()
    os_info = _detect_os_details()
    hostname = socket.gethostname()

    try:
        raw_mac = uuid.getnode()
        mac_address = ':'.join(f'{(raw_mac >> ele) & 0xff:02x}' for ele in range(40, -8, -8))
    except Exception:
        mac_address = "unknown"

    if not force_reset and filepath.exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("machine_id"):
                    return MachineIdentity(
                        machine_id=data["machine_id"],
                        hostname=hostname, # update dynamic hostname if changed
                        os_type=os_info["os_type"],
                        os_name=os_info["os_name"],
                        os_version=os_info["os_version"],
                        architecture=os_info["architecture"],
                        mac_address=mac_address
                    )
        except Exception:
            pass # Re-generate on read error

    # Generate new deterministic machine identity
    seed = _get_hardware_seed()
    digest = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:12].upper()
    machine_id = f"JOCKY-{digest}"

    record = {
        "machine_id": machine_id,
        "hardware_seed_hash": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
        "created_at": platform.node(),
        "hostname": hostname,
        "os_type": os_info["os_type"],
        "os_name": os_info["os_name"],
        "os_version": os_info["os_version"],
        "architecture": os_info["architecture"],
        "mac_address": mac_address
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
    except Exception as e:
        print(f"[Warning] Failed to write machine identity file: {e}", file=sys.stderr)

    return MachineIdentity(
        machine_id=machine_id,
        hostname=hostname,
        os_type=os_info["os_type"],
        os_name=os_info["os_name"],
        os_version=os_info["os_version"],
        architecture=os_info["architecture"],
        mac_address=mac_address
    )
