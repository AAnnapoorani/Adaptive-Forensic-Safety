from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class CorrelationMatchResult:
    rule_name: str
    status_label: str  # "indicator detected", "correlation rule matched"
    confidence: str  # "rule_based"
    description: str
    rule_id: str = ""
    matched: bool = True
    reason: str = ""
    severity: str = "HIGH"
    evidence: list[Any] = field(default_factory=list)
    matched_data: dict[str, Any] = field(default_factory=dict)
    recommended_operations: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = self.rule_name
        if not self.reason:
            self.reason = self.description
        if not self.evidence and self.matched_data:
            for k in ("connections", "executable_files", "spawn_events"):
                if k in self.matched_data:
                    self.evidence = self.matched_data[k]
                    break

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class CorrelationEngine:
    """Deterministic, rule-based forensic correlation engine."""

    def evaluate(self, collected_evidence: dict[str, Any]) -> list[CorrelationMatchResult]:
        """
        Evaluate correlation rules against all collected evidence so far.
        collected_evidence map: { "PROCESS.LIST": [...], "NETWORK.CONNECTIONS": [...], ... }
        """
        matches: list[CorrelationMatchResult] = []

        raw_processes = collected_evidence.get("PROCESS.LIST", [])
        processes = [p for p in raw_processes if isinstance(p, dict)] if isinstance(raw_processes, list) else []

        raw_network = collected_evidence.get("NETWORK.CONNECTIONS", [])
        network = [c for c in raw_network if isinstance(c, dict)] if isinstance(raw_network, list) else []

        raw_files = collected_evidence.get("FILES.RECENT", [])
        files = [f for f in raw_files if isinstance(f, dict)] if isinstance(raw_files, list) else []

        raw_hierarchy = collected_evidence.get("PROCESS.PARENT_CHILD", [])
        hierarchy = [h for h in raw_hierarchy if isinstance(h, dict)] if isinstance(raw_hierarchy, list) else []

        # -------------------------------------------------------------
        # Rule 1: POWERSHELL_NETWORK_ACTIVITY
        # Condition: powershell.exe has active or external network connection
        # -------------------------------------------------------------
        ps_pids = set()
        for p in processes:
            pname = (p.get("name") or "").lower()
            if pname in ("powershell.exe", "pwsh.exe"):
                ps_pids.add(p.get("pid"))

        ps_net_matches = []
        for conn in network:
            pname = (conn.get("process_name") or "").lower()
            pid = conn.get("pid")
            is_ps = (pid in ps_pids) or (pname in ("powershell.exe", "pwsh.exe"))
            
            if is_ps and (conn.get("is_external") or conn.get("remote_address")):
                ps_net_matches.append(conn)

        if ps_net_matches:
            matches.append(CorrelationMatchResult(
                rule_name="POWERSHELL_NETWORK_ACTIVITY",
                status_label="indicator detected",
                confidence="rule_based",
                description="PowerShell process established or possesses an external network connection.",
                matched_data={
                    "connection_count": len(ps_net_matches),
                    "connections": ps_net_matches[:5]
                },
                recommended_operations=[
                    "PROCESS.PARENT_CHILD",
                    "COMMANDLINE.INFO",
                    "FILES.RECENT"
                ]
            ))

        # -------------------------------------------------------------
        # Rule 2: SUSPICIOUS_NETWORK_PROCESS
        # Condition: Administrative or script utility with external network socket
        # -------------------------------------------------------------
        MONITORED_BINARIES = {"cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe", "certutil.exe", "curl.exe"}
        suspicious_net = []
        for conn in network:
            pname = (conn.get("process_name") or "").lower()
            if pname in MONITORED_BINARIES and conn.get("is_external"):
                suspicious_net.append(conn)

        if suspicious_net:
            matches.append(CorrelationMatchResult(
                rule_name="SUSPICIOUS_NETWORK_PROCESS",
                status_label="correlation rule matched",
                confidence="rule_based",
                description="Monitored script or utility binary observed with active external network communication.",
                matched_data={"matched_count": len(suspicious_net), "connections": suspicious_net[:5]},
                recommended_operations=[
                    "PROCESS.PARENT_CHILD",
                    "COMMANDLINE.INFO"
                ]
            ))

        # -------------------------------------------------------------
        # Rule 3: RECENT_EXECUTABLE_IN_MONITORED_DIR
        # Condition: Executable or script file detected in monitored directory
        # -------------------------------------------------------------
        exec_files = [f for f in files if isinstance(f, dict) and f.get("is_executable")]
        if exec_files:
            matches.append(CorrelationMatchResult(
                rule_name="RECENT_EXECUTABLE_IN_MONITORED_DIR",
                status_label="indicator detected",
                confidence="rule_based",
                description="Recently created or modified executable/script artifact present in monitored directory.",
                matched_data={"executable_files": exec_files[:5]},
                recommended_operations=[
                    "FILE.HASH",
                    "PROCESS.PARENT_CHILD"
                ]
            ))

        # -------------------------------------------------------------
        # Rule 4: SUSPICIOUS_PARENT_CHILD_SPAWN
        # Condition: explorer or office application directly spawning shell/scripting host
        # -------------------------------------------------------------
        shell_spawns = []
        for edge in hierarchy:
            if not isinstance(edge, dict):
                continue
            parent = (edge.get("parent_name") or "").lower()
            child = (edge.get("child_name") or "").lower()
            if child in ("powershell.exe", "cmd.exe", "mshta.exe"):
                if parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"):
                    shell_spawns.append(edge)

        if shell_spawns:
            matches.append(CorrelationMatchResult(
                rule_name="SUSPICIOUS_PARENT_CHILD_SPAWN",
                status_label="correlation rule matched",
                confidence="rule_based",
                description="Office or reader application spawned command-line interpreter or script runner.",
                matched_data={"spawn_events": shell_spawns},
                recommended_operations=[
                    "COMMANDLINE.INFO",
                    "FILES.RECENT"
                ]
            ))

        # -------------------------------------------------------------
        # Rule 5: BYOVD_VULNERABLE_DRIVER_LOADED
        # Condition: A known-vulnerable (BYOVD) driver is loaded in kernel space
        # -------------------------------------------------------------
        raw_drivers = collected_evidence.get("DRIVERS.LIST", [])
        drivers = [d for d in raw_drivers if isinstance(d, dict)] if isinstance(raw_drivers, list) else []
        byovd_hits = [d for d in drivers if d.get("is_byovd_known_vulnerable")]
        critical_byovd = [d for d in byovd_hits if d.get("byovd_risk") == "CRITICAL"]
        if byovd_hits:
            matches.append(CorrelationMatchResult(
                rule_name="BYOVD_VULNERABLE_DRIVER_LOADED",
                status_label="indicator detected",
                confidence="rule_based",
                description=(
                    f"Bring-Your-Own-Vulnerable-Driver (BYOVD) attack detected: "
                    f"{len(byovd_hits)} known-vulnerable kernel driver(s) loaded. "
                    f"{len(critical_byovd)} CRITICAL severity (capable of disabling EDR/AV callbacks)."
                ),
                severity="CRITICAL" if critical_byovd else "HIGH",
                matched_data={
                    "byovd_count": len(byovd_hits),
                    "critical_count": len(critical_byovd),
                    "vulnerable_drivers": byovd_hits[:5]
                },
                recommended_operations=[
                    "MEMORY.ANALYSIS",
                    "PROCESS.LIST",
                    "COMMANDLINE.INFO",
                    "EVENTLOG.RECENT"
                ]
            ))

        # -------------------------------------------------------------
        # Rule 6: IN_MEMORY_INJECTION_DETECTED
        # Condition: Private committed executable memory regions found in process VAD
        # These are the primary indicators of: process hollowing, reflective DLL
        # injection, shellcode injection, and thread execution hijacking
        # -------------------------------------------------------------
        raw_memory = collected_evidence.get("MEMORY.ANALYSIS", [])
        memory_regions = [r for r in raw_memory if isinstance(r, dict)] if isinstance(raw_memory, list) else []
        if memory_regions:
            high_severity = [r for r in memory_regions if r.get("severity") == "HIGH"]
            injected_pids = list({r["pid"] for r in memory_regions if r.get("pid")})
            injected_procs = list({r["process_name"] for r in memory_regions if r.get("process_name")})
            if high_severity:
                matches.append(CorrelationMatchResult(
                    rule_name="IN_MEMORY_INJECTION_DETECTED",
                    status_label="indicator detected",
                    confidence="rule_based",
                    description=(
                        f"In-memory code injection detected: {len(memory_regions)} anomalous private executable "
                        f"memory region(s) found across {len(injected_pids)} process(es) ({', '.join(injected_procs[:3])}). "
                        f"Techniques indicated: process hollowing, reflective DLL injection, or shellcode injection."
                    ),
                    severity="CRITICAL",
                    matched_data={
                        "suspicious_region_count": len(memory_regions),
                        "high_severity_count": len(high_severity),
                        "affected_processes": injected_procs,
                        "regions": high_severity[:3]
                    },
                    recommended_operations=[
                        "PROCESS.PARENT_CHILD",
                        "COMMANDLINE.INFO",
                        "NETWORK.CONNECTIONS",
                        "FILE.HASH"
                    ]
                ))

        return matches
