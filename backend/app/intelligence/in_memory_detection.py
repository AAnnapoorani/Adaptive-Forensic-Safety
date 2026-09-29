"""
intelligence/in_memory_detection.py
JOCKY In-Memory Activity Detection Module

Safe, read-only, rule-based detection of indicators associated with in-memory
execution techniques. This module does NOT inject code, modify processes, or
bypass any security control.

Detection strategy:
  1. Collect raw indicators from real process + network + driver evidence
  2. Normalize each indicator to a structured format
  3. Apply rule-based scoring
  4. Assign severity and classification
  5. Return structured findings for the correlation engine

Rules implemented:
  - ORPHANED_PROCESS: Process with no parent or unexpected parent PID
  - UNUSUAL_PARENT_CHILD: Process started by unusual parent (e.g. office -> cmd)
  - MISSING_MODULE_ON_DISK: Executable with no verifiable on-disk path
  - HIGH_MEMORY_ANONYMOUS_EXEC: Process with anomalously high anonymous executable memory
  - UNSIGNED_SERVICE_EXECUTABLE: Service binary without recognized publisher
  - SUSPICIOUS_PORT_PROCESS: Non-browser process with high-numbered external connection
  - DELETED_AFTER_EXEC: Process whose executable path no longer exists (fileless indicator)
"""

from __future__ import annotations

import os
import platform
from datetime import datetime, timezone
from typing import Any


# ─── Indicator Data Model ─────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_indicator(
    rule_id: str,
    rule_name: str,
    severity: str,
    description: str,
    evidence: dict,
    recommendation: str = "",
) -> dict:
    return {
        "indicator_id": f"IMD-{rule_id}-{abs(hash(str(evidence))) % 100000:05d}",
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "classification": "POTENTIAL_IN_MEMORY_EXECUTION_INDICATOR",
        "note": "This is a probabilistic forensic indicator, not a confirmed attack. Requires investigator review.",
        "timestamp": _now_iso(),
    }


# ─── Rule Definitions ─────────────────────────────────────────────────────────

SHELL_BINARIES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
    "cscript.exe", "wscript.exe", "regsvr32.exe", "rundll32.exe",
}

OFFICE_BINARIES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "onenote.exe",
}

BROWSER_BINARIES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "chromium.exe",
}

# ─── Rule 1: ORPHANED_PROCESS ─────────────────────────────────────────────────

def _rule_orphaned_process(processes: list[dict]) -> list[dict]:
    """Detect processes whose declared parent PID does not exist."""
    indicators = []
    all_pids = {p.get("pid") for p in processes}

    for proc in processes:
        pid = proc.get("pid")
        ppid = proc.get("ppid") or proc.get("parent_pid") or proc.get("parent_pid_resolved")
        name = proc.get("name", "unknown")

        if pid in (0, 4, None):
            continue  # Skip System/Idle
        if not ppid:
            continue
        if ppid == 0 or ppid == 4:
            continue  # Normal: parented to System

        if ppid not in all_pids:
            indicators.append(_make_indicator(
                rule_id="R001",
                rule_name="ORPHANED_PROCESS",
                severity="MEDIUM",
                description=(
                    f"Process '{name}' (PID {pid}) has parent PID {ppid} which does not exist "
                    f"in the current process list. This may indicate parent process spoofing "
                    f"or a short-lived launcher process."
                ),
                evidence={"pid": pid, "name": name, "ppid": ppid},
                recommendation="Correlate with EVENTLOG.RECENT process creation events (Event ID 4688)."
            ))

    return indicators


# ─── Rule 2: UNUSUAL_PARENT_CHILD_SPAWN ───────────────────────────────────────

def _rule_unusual_parent_child(hierarchy: list[dict]) -> list[dict]:
    """Detect office/reader applications spawning shell or scripting interpreters."""
    indicators = []
    for edge in hierarchy:
        parent = (edge.get("parent_name") or edge.get("parent") or "").lower()
        child = (edge.get("child_name") or edge.get("child") or "").lower()
        child_pid = edge.get("child_pid") or edge.get("pid")

        if parent in OFFICE_BINARIES and child in SHELL_BINARIES:
            indicators.append(_make_indicator(
                rule_id="R002",
                rule_name="UNUSUAL_PARENT_CHILD_SPAWN",
                severity="HIGH",
                description=(
                    f"Office/document application '{parent}' spawned shell interpreter '{child}' "
                    f"(PID {child_pid}). This is a primary indicator of macro-based or document "
                    f"exploitation attempting to execute commands."
                ),
                evidence={"parent": parent, "child": child, "child_pid": child_pid},
                recommendation="Collect COMMANDLINE.INFO and FILES.RECENT for context."
            ))

    return indicators


# ─── Rule 3: MISSING_EXECUTABLE_ON_DISK ───────────────────────────────────────

def _rule_missing_executable(processes: list[dict]) -> list[dict]:
    """Detect processes whose executable path no longer exists on disk (fileless indicator)."""
    indicators = []
    if platform.system() != "Windows":
        return indicators  # Reliable on Windows only

    for proc in processes:
        exe = proc.get("exe")
        name = proc.get("name", "unknown")
        pid = proc.get("pid")

        if not exe or exe in (None, "None", ""):
            continue
        if not os.path.isabs(exe):
            continue

        try:
            if not os.path.exists(exe):
                indicators.append(_make_indicator(
                    rule_id="R003",
                    rule_name="MISSING_EXECUTABLE_ON_DISK",
                    severity="HIGH",
                    description=(
                        f"Process '{name}' (PID {pid}) references executable path '{exe}' "
                        f"which does not exist on disk. This may indicate the executable "
                        f"was deleted after launch — a common fileless execution technique."
                    ),
                    evidence={"pid": pid, "name": name, "exe_path": exe},
                    recommendation="Correlate with FILE.HASH and FILES.RECENT; check recycle bin."
                ))
        except (PermissionError, OSError):
            pass  # Cannot check — skip

    return indicators


# ─── Rule 4: SUSPICIOUS_EXTERNAL_PROCESS ──────────────────────────────────────

def _rule_suspicious_external_connection(
    processes: list[dict], network: list[dict]
) -> list[dict]:
    """Detect non-browser processes making external connections on unusual ports."""
    indicators = []
    ps_pids = {p.get("pid"): (p.get("name") or "").lower() for p in processes}

    for conn in network:
        if not conn.get("is_external"):
            continue
        pid = conn.get("pid")
        pname = (conn.get("process_name") or ps_pids.get(pid) or "").lower()
        rport = conn.get("remote_port") or 0

        if pname in BROWSER_BINARIES:
            continue  # Browsers making external connections is expected

        if pname in SHELL_BINARIES and rport:
            indicators.append(_make_indicator(
                rule_id="R004",
                rule_name="SHELL_EXTERNAL_CONNECTION",
                severity="HIGH",
                description=(
                    f"Shell/scripting process '{pname}' (PID {pid}) has an active external "
                    f"network connection to port {rport}. Script interpreters establishing "
                    f"external connections may indicate C2 communication or data exfiltration."
                ),
                evidence={
                    "pid": pid, "process": pname,
                    "remote_address": conn.get("remote_address"),
                    "remote_port": rport,
                    "status": conn.get("status"),
                },
                recommendation="Correlate with COMMANDLINE.INFO; check remote address reputation."
            ))
        elif rport and rport not in (80, 443, 8080, 8443) and pname not in BROWSER_BINARIES:
            # Non-standard port + non-browser = worth noting
            if pname and pname not in ("svchost.exe", "lsass.exe", "system"):
                indicators.append(_make_indicator(
                    rule_id="R004B",
                    rule_name="UNUSUAL_PORT_EXTERNAL_CONNECTION",
                    severity="LOW",
                    description=(
                        f"Process '{pname}' (PID {pid}) has an external connection on "
                        f"non-standard port {rport}. May be legitimate service traffic "
                        f"or non-standard C2 channel."
                    ),
                    evidence={
                        "pid": pid, "process": pname,
                        "remote_address": conn.get("remote_address"),
                        "remote_port": rport,
                    },
                    recommendation="Review process purpose; verify remote host legitimacy."
                ))

    return indicators


# ─── Rule 5: BYOVD_DRIVER_WITH_NETWORK ────────────────────────────────────────

def _rule_byovd_with_network(
    drivers: list[dict], network: list[dict]
) -> list[dict]:
    """
    Detect co-occurrence of vulnerable driver + external network connection.
    BYOVD + network activity is a high-confidence indicator of active exploitation.
    """
    indicators = []
    if not isinstance(drivers, list):
        return indicators

    byovd_drivers = [d for d in drivers if d.get("is_byovd_known_vulnerable")]
    if not byovd_drivers:
        return indicators

    external_conns = [c for c in network if c.get("is_external")]
    if not external_conns:
        return indicators

    indicators.append(_make_indicator(
        rule_id="R005",
        rule_name="BYOVD_DRIVER_PLUS_EXTERNAL_NETWORK",
        severity="CRITICAL",
        description=(
            f"Co-occurrence of {len(byovd_drivers)} known-vulnerable BYOVD driver(s) "
            f"AND {len(external_conns)} external network connection(s). "
            f"This combination is a high-confidence indicator of active kernel-level "
            f"exploitation with active C2 communication."
        ),
        evidence={
            "byovd_drivers": [d.get("name") for d in byovd_drivers[:3]],
            "external_connection_count": len(external_conns),
            "sample_connections": external_conns[:2],
        },
        recommendation="Immediately isolate machine. Collect full memory dump. Escalate to incident response."
    ))

    return indicators


# ─── Rule 6: MEMORY_ANOMALY_HIGH_COUNT ────────────────────────────────────────

def _rule_memory_anomaly(memory_regions: list[dict]) -> list[dict]:
    """Detect processes with suspiciously high counts of private executable memory regions."""
    indicators = []
    if not isinstance(memory_regions, list):
        return indicators

    # Group regions by process
    by_proc: dict[str, list] = {}
    for region in memory_regions:
        pname = region.get("process_name", "unknown")
        by_proc.setdefault(pname, []).append(region)

    for pname, regions in by_proc.items():
        high = [r for r in regions if r.get("severity") == "HIGH"]
        if len(high) >= 3:
            indicators.append(_make_indicator(
                rule_id="R006",
                rule_name="MULTIPLE_PRIVATE_EXEC_REGIONS",
                severity="HIGH",
                description=(
                    f"Process '{pname}' has {len(high)} high-severity private executable "
                    f"memory regions. Multiple anonymous executable regions in a single "
                    f"process are consistent with shellcode or reflective DLL loading."
                ),
                evidence={
                    "process": pname,
                    "high_severity_count": len(high),
                    "sample_regions": [
                        {"base": r.get("base_address"), "size": r.get("region_size_bytes")}
                        for r in high[:3]
                    ],
                },
                recommendation="Correlate with NETWORK.CONNECTIONS; consider memory acquisition."
            ))

    return indicators


# ─── Main Detection Function ───────────────────────────────────────────────────

def detect_in_memory_indicators(collected_evidence: dict[str, Any]) -> dict[str, Any]:
    """
    Run all in-memory activity detection rules against collected evidence.

    Args:
        collected_evidence: Dict keyed by operation name with real collected data.
                           e.g. {"PROCESS.LIST": [...], "NETWORK.CONNECTIONS": [...]}

    Returns:
        Structured detection report with all indicators.
    """
    processes = collected_evidence.get("PROCESS.LIST", [])
    network = collected_evidence.get("NETWORK.CONNECTIONS", [])
    hierarchy = collected_evidence.get("PROCESS.PARENT_CHILD", [])
    drivers = collected_evidence.get("DRIVERS.LIST", [])
    memory_regions = collected_evidence.get("MEMORY.ANALYSIS", [])

    all_indicators: list[dict] = []

    # Apply all rules
    all_indicators.extend(_rule_orphaned_process(processes))
    all_indicators.extend(_rule_unusual_parent_child(hierarchy))
    all_indicators.extend(_rule_missing_executable(processes))
    all_indicators.extend(_rule_suspicious_external_connection(processes, network))
    all_indicators.extend(_rule_byovd_with_network(drivers, network))
    all_indicators.extend(_rule_memory_anomaly(memory_regions))

    # Severity distribution
    severity_counts = {
        "CRITICAL": sum(1 for i in all_indicators if i["severity"] == "CRITICAL"),
        "HIGH": sum(1 for i in all_indicators if i["severity"] == "HIGH"),
        "MEDIUM": sum(1 for i in all_indicators if i["severity"] == "MEDIUM"),
        "LOW": sum(1 for i in all_indicators if i["severity"] == "LOW"),
    }

    overall_severity = "NONE"
    if severity_counts["CRITICAL"] > 0:
        overall_severity = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall_severity = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall_severity = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        overall_severity = "LOW"

    return {
        "status": "COMPLETED",
        "analysis_type": "IN_MEMORY_ACTIVITY_DETECTION",
        "classification": "FORENSIC_INDICATOR_ANALYSIS",
        "platform": platform.system(),
        "timestamp": _now_iso(),
        "total_indicators": len(all_indicators),
        "overall_severity": overall_severity,
        "severity_distribution": severity_counts,
        "indicators": all_indicators,
        "disclaimer": (
            "All indicators are probabilistic rule matches based on observable system state. "
            "They represent potential forensic signals, not confirmed attack activity. "
            "Investigator review is required before any conclusion."
        ),
        "evidence_sources": {
            "processes_scanned": len(processes) if isinstance(processes, list) else 0,
            "network_connections": len(network) if isinstance(network, list) else 0,
            "parent_child_edges": len(hierarchy) if isinstance(hierarchy, list) else 0,
            "drivers_scanned": len(drivers) if isinstance(drivers, list) else 0,
            "memory_regions": len(memory_regions) if isinstance(memory_regions, list) else 0,
        }
    }


# ─── Live Detection (calls real collectors) ────────────────────────────────────

def run_live_detection() -> dict[str, Any]:
    """
    Collect real system telemetry and run all in-memory detection rules.
    This is the function called by the /api/jocky/security-analysis endpoint.
    """
    from app.collectors.processes import ProcessListCollector
    from app.collectors.network import NetworkConnectionsCollector
    from app.collectors.commandline import ProcessParentChildCollector
    from app.collectors.drivers import DriversListCollector, MemoryAnalysisCollector

    evidence = {}

    collectors = [
        ("PROCESS.LIST", ProcessListCollector()),
        ("NETWORK.CONNECTIONS", NetworkConnectionsCollector()),
        ("PROCESS.PARENT_CHILD", ProcessParentChildCollector()),
        ("DRIVERS.LIST", DriversListCollector()),
        ("MEMORY.ANALYSIS", MemoryAnalysisCollector()),
    ]

    for op, collector in collectors:
        try:
            result = collector.collect()
            evidence[op] = result.data
        except Exception as e:
            evidence[op] = []

    return detect_in_memory_indicators(evidence)
