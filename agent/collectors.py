"""
JOCKY Agent — OS-Specific & Common Telemetry Collectors with Live Sigma/YARA Rules

Collects real, live host telemetry using psutil and native OS APIs:
  - System metrics (CPU, RAM, Disk, Network)
  - Live process table snapshots with Sigma/YARA threat heuristic scanning
  - Forensic security events (suspicious executions, obfuscation, ransomware patterns)
"""

import re
import os
import time
import socket
import platform
from datetime import datetime, timezone
import psutil

# Track network deltas for upload/download speed calculation
_last_net_io = None
_last_net_time = None

# Built-in Sigma / YARA Heuristic Detection Rules
SIGMA_RULES = [
    {
        "id": "SIGMA-001",
        "name": "Encoded PowerShell Scriptblock",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(powershell|pwsh).*(?:-enc|-encodedcommand|-w\s+hidden|iex\b|downloadstring)", re.IGNORECASE),
        "description": "Obfuscated PowerShell execution using Base64 encoding or hidden window"
    },
    {
        "id": "SIGMA-002",
        "name": "Offensive Security & Lateral Movement Tooling",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(mimikatz|cobaltstrike|chisel|psexec|procdump|lazagne|rubeus|bloodhound|sharpdump)\b", re.IGNORECASE),
        "description": "Known offensive credential extraction or lateral movement utility"
    },
    {
        "id": "SIGMA-003",
        "name": "Shadow Copy Deletion / Ransomware Indicator",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(vssadmin.*delete.*shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no)", re.IGNORECASE),
        "description": "Ransomware pre-encryption step attempting to purge system restore points"
    },
    {
        "id": "SIGMA-004",
        "name": "System Utility Ingress Tool (LOLBAS)",
        "severity": "HIGH",
        "pattern": re.compile(r"(certutil.*-urlcache|bitsadmin.*\/transfer|curl.*\|\s*sh|wget.*\|\s*bash)", re.IGNORECASE),
        "description": "Living-off-the-land binary abused for remote payload staging"
    },
    {
        "id": "SIGMA-005",
        "name": "Network Reconnaissance Utility",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\b(nmap|masscan|tcpdump|wireshark|advanced_ip_scanner|nltest\.exe)\b", re.IGNORECASE),
        "description": "Active reconnaissance tool scanning internal subnet assets"
    }
]

# Standard System paths for path impersonation detection
WINDOWS_SYS_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows")
PROTECTED_SYS_NAMES = {"svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe"}


def _utc_iso():
    return datetime.now(timezone.utc).isoformat()


def scan_process_heuristics(name: str, exe_path: str | None, cmdline: str) -> tuple[str, list[str]]:
    """
    Evaluates running process properties against Sigma / YARA rules.
    Returns (threat_level, matched_rules_list).
    """
    threat_level = "CLEAN"
    matched_rules = []
    combined_target = f"{name} {exe_path or ''} {cmdline}"

    # 1. Regex rule scanning
    for rule in SIGMA_RULES:
        if rule["pattern"].search(combined_target):
            matched_rules.append(f"{rule['id']}: {rule['name']}")
            # Escalate threat level
            if rule["severity"] == "CRITICAL":
                threat_level = "CRITICAL"
            elif rule["severity"] == "HIGH" and threat_level != "CRITICAL":
                threat_level = "HIGH"
            elif rule["severity"] == "MEDIUM" and threat_level not in ("CRITICAL", "HIGH"):
                threat_level = "MEDIUM"

    # 2. Path impersonation check on Windows
    name_lower = name.lower()
    if platform.system() == "Windows" and name_lower in PROTECTED_SYS_NAMES and exe_path:
        exe_lower = exe_path.lower()
        if not any(exe_lower.startswith(d) for d in WINDOWS_SYS_DIRS):
            matched_rules.append(f"SIGMA-006: Masquerading System Process ({name} outside System32)")
            threat_level = "CRITICAL"

    return threat_level, matched_rules


def collect_system_metrics() -> dict:
    """Collect real-time CPU, RAM, Disk, and Network telemetry."""
    global _last_net_io, _last_net_time

    # CPU metrics
    cpu_percent = psutil.cpu_percent(interval=0.15)
    cpu_cores = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()
    cpu_freq_mhz = round(cpu_freq.current, 1) if cpu_freq else None

    # Memory metrics
    mem = psutil.virtual_memory()
    memory_total = mem.total
    memory_used = mem.used
    memory_available = mem.available
    memory_percent = mem.percent

    # Disk metrics (system partition)
    try:
        if platform.system() == "Windows":
            disk_path = "C:\\"
        else:
            disk_path = "/"
        disk = psutil.disk_usage(disk_path)
        disk_total = disk.total
        disk_used = disk.used
        disk_free = disk.free
        disk_percent = disk.percent
    except Exception:
        disk_total = 0
        disk_used = 0
        disk_free = 0
        disk_percent = 0.0

    # Network rate calculation
    net_io = psutil.net_io_counters()
    now_t = time.time()
    upload_speed = 0.0
    download_speed = 0.0

    if _last_net_io is not None and _last_net_time is not None:
        dt = max(now_t - _last_net_time, 0.1)
        upload_speed = max((net_io.bytes_sent - _last_net_io.bytes_sent) / dt, 0.0)
        download_speed = max((net_io.bytes_recv - _last_net_io.bytes_recv) / dt, 0.0)

    _last_net_io = net_io
    _last_net_time = now_t

    # Active network sockets count
    try:
        active_conns = len(psutil.net_connections(kind='inet'))
    except (psutil.AccessDenied, Exception):
        active_conns = 0

    return {
        "timestamp": _utc_iso(),
        "cpu_percent": round(cpu_percent, 1),
        "cpu_cores": cpu_cores,
        "cpu_freq_mhz": cpu_freq_mhz,
        "memory_total_bytes": memory_total,
        "memory_used_bytes": memory_used,
        "memory_available_bytes": memory_available,
        "memory_percent": round(memory_percent, 1),
        "disk_total_bytes": disk_total,
        "disk_used_bytes": disk_used,
        "disk_free_bytes": disk_free,
        "disk_percent": round(disk_percent, 1),
        "network_bytes_sent": net_io.bytes_sent,
        "network_bytes_recv": net_io.bytes_recv,
        "network_upload_speed": round(upload_speed, 1),
        "network_download_speed": round(download_speed, 1),
        "active_connections": active_conns
    }


def collect_processes(limit: int = 35) -> list[dict]:
    """Collect top active processes with Sigma/YARA threat analysis."""
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'create_time', 'cmdline']):
        try:
            info = p.info
            p_name = info.get('name') or f"proc-{info.get('pid')}"
            try:
                exe = p.exe()
            except Exception:
                exe = None

            try:
                rss = p.memory_info().rss
            except Exception:
                rss = 0

            create_dt = None
            if info.get('create_time'):
                create_dt = datetime.fromtimestamp(info['create_time'], tz=timezone.utc).isoformat()

            cmdline = " ".join(info.get('cmdline') or [])
            threat_level, matched_rules = scan_process_heuristics(p_name, exe, cmdline)

            procs.append({
                "pid": info['pid'],
                "name": p_name,
                "exe_path": exe,
                "username": info.get('username') or "SYSTEM",
                "cpu_percent": round(info.get('cpu_percent') or 0.0, 1),
                "memory_percent": round(info.get('memory_percent') or 0.0, 1),
                "memory_rss_bytes": rss,
                "status": info.get('status') or "running",
                "create_time": create_dt,
                "threat_level": threat_level,
                "matched_rules": matched_rules
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Priority sort: Threats first, then CPU + Memory
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "CLEAN": 3}
    procs.sort(key=lambda x: (
        severity_order.get(x.get('threat_level', 'CLEAN'), 3),
        -(x.get('cpu_percent', 0.0) + x.get('memory_percent', 0.0))
    ))
    return procs[:limit]


_seen_event_keys = set()

def detect_forensic_events(machine_id: str) -> list[dict]:
    """
    Inspect live process executions and network activity to generate
    structured forensic events when suspicious indicators are detected.
    """
    events = []
    current_time = _utc_iso()

    for p in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        try:
            name = p.info.get('name') or ''
            pid = p.info.get('pid')
            username = p.info.get('username') or "UNKNOWN"
            cmdline = " ".join(p.info.get('cmdline') or [])

            try:
                exe = p.exe()
            except Exception:
                exe = None

            threat_level, matched_rules = scan_process_heuristics(name, exe, cmdline)
            if threat_level in ("CRITICAL", "HIGH"):
                event_key = f"{machine_id}:{pid}:{threat_level}"
                if event_key not in _seen_event_keys:
                    _seen_event_keys.add(event_key)
                    events.append({
                        "event_type": "THREAT_HEURISTIC_TRIGGER",
                        "severity": threat_level,
                        "source": f"{platform.system()} Forensic Auditor",
                        "description": f"Process '{name}' (PID {pid}) matched: {', '.join(matched_rules)}",
                        "process_name": name,
                        "pid": pid,
                        "user": username,
                        "timestamp": current_time,
                        "requires_autonomous_investigation": True,
                        "metadata_json": f'{{"rules": {matched_rules}, "cmdline": "{cmdline[:250]}"}}'
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if len(_seen_event_keys) > 500:
        _seen_event_keys.clear()

    return events
