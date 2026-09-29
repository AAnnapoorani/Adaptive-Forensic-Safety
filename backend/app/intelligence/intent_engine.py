from dataclasses import dataclass, field

@dataclass
class IntentProfile:
    intent_id: str
    display_name: str
    description: str
    initial_operations: list[str]
    adaptive_operations: list[str] = field(default_factory=list)
    priority_map: dict[str, int] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

DEFAULT_INTENT_PROFILES: dict[str, IntentProfile] = {
    "suspicious_network_activity": IntentProfile(
        intent_id="suspicious_network_activity",
        display_name="Suspicious Network Activity",
        description="Investigates anomalous network sockets, outbound command-and-control beacons, and external process connections.",
        initial_operations=[
            "SYSTEM.INFO",
            "PROCESS.LIST",
            "NETWORK.CONNECTIONS",
            "DNS.INFO"
        ],
        adaptive_operations=[
            "PROCESS.PARENT_CHILD",
            "COMMANDLINE.INFO",
            "FILES.RECENT"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "PROCESS.LIST": 2,
            "NETWORK.CONNECTIONS": 2,
            "DNS.INFO": 2,
            "PROCESS.PARENT_CHILD": 4,
            "COMMANDLINE.INFO": 4,
            "FILES.RECENT": 4
        },
        tags=["network", "socket", "dns", "powershell", "c2"]
    ),
    "possible_malware_execution": IntentProfile(
        intent_id="possible_malware_execution",
        display_name="Possible Malware Execution",
        description="Investigates suspicious binary execution, dropped executables, unverified command lines, and persistence markers.",
        initial_operations=[
            "SYSTEM.INFO",
            "PROCESS.LIST",
            "FILES.RECENT",
            "EVENTLOG.RECENT"
        ],
        adaptive_operations=[
            "FILE.HASH",
            "PROCESS.PARENT_CHILD",
            "COMMANDLINE.INFO",
            "NETWORK.CONNECTIONS"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "PROCESS.LIST": 2,
            "FILES.RECENT": 2,
            "EVENTLOG.RECENT": 3,
            "PROCESS.PARENT_CHILD": 4,
            "COMMANDLINE.INFO": 4,
            "FILE.HASH": 4,
            "NETWORK.CONNECTIONS": 4
        },
        tags=["malware", "binary", "hash", "execution", "process_tree"]
    ),
    "system_compromise": IntentProfile(
        intent_id="system_compromise",
        display_name="System Compromise Assessment",
        description="Comprehensive investigative triage across active accounts, system metrics, processes, network sockets, and recent logs.",
        initial_operations=[
            "SYSTEM.INFO",
            "USERS.LIST",
            "PROCESS.LIST",
            "NETWORK.CONNECTIONS",
            "EVENTLOG.RECENT"
        ],
        adaptive_operations=[
            "PROCESS.PARENT_CHILD",
            "COMMANDLINE.INFO",
            "DNS.INFO"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "USERS.LIST": 2,
            "PROCESS.LIST": 2,
            "NETWORK.CONNECTIONS": 2,
            "EVENTLOG.RECENT": 3,
            "FILES.RECENT": 3,
            "PROCESS.PARENT_CHILD": 4,
            "COMMANDLINE.INFO": 4,
            "DNS.INFO": 4
        },
        tags=["triage", "compromise", "accounts", "incident_response"]
    ),
    # ── New Evasion-Aware Intent Profiles (Gap implementations) ───────────────────
    "kernel_evasion_analysis": IntentProfile(
        intent_id="kernel_evasion_analysis",
        display_name="Kernel-Level Evasion & BYOVD Detection",
        description="Detects Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks by enumerating all loaded "
                    "kernel-mode drivers via direct Win32 EnumDeviceDrivers API (ctypes, low EDR visibility) "
                    "and cross-referencing against a curated CVE-linked vulnerable driver database.",
        initial_operations=[
            "SYSTEM.INFO",
            "DRIVERS.LIST",
            "PROCESS.LIST"
        ],
        adaptive_operations=[
            "MEMORY.ANALYSIS",
            "COMMANDLINE.INFO",
            "EVENTLOG.RECENT"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "DRIVERS.LIST": 2,
            "PROCESS.LIST": 2,
            "MEMORY.ANALYSIS": 3,
            "COMMANDLINE.INFO": 4,
            "EVENTLOG.RECENT": 4
        },
        tags=["byovd", "kernel", "driver", "edr_evasion", "rootkit"]
    ),
    "memory_injection_hunt": IntentProfile(
        intent_id="memory_injection_hunt",
        display_name="In-Memory Code Injection Hunt",
        description="Scans all running process virtual address spaces via direct VirtualQueryEx (ctypes kernel32) "
                    "to detect private committed executable memory regions — primary indicators of process "
                    "hollowing, reflective DLL injection, shellcode injection, and thread hijacking.",
        initial_operations=[
            "SYSTEM.INFO",
            "PROCESS.LIST",
            "MEMORY.ANALYSIS"
        ],
        adaptive_operations=[
            "PROCESS.PARENT_CHILD",
            "COMMANDLINE.INFO",
            "FILE.HASH",
            "NETWORK.CONNECTIONS"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "PROCESS.LIST": 2,
            "MEMORY.ANALYSIS": 2,
            "PROCESS.PARENT_CHILD": 3,
            "COMMANDLINE.INFO": 3,
            "FILE.HASH": 4,
            "NETWORK.CONNECTIONS": 4
        },
        tags=["injection", "hollowing", "reflective_dll", "shellcode", "in_memory"]
    ),
    "byovd_detection": IntentProfile(
        intent_id="byovd_detection",
        display_name="BYOVD Full Spectrum Detection",
        description="Combined kernel driver enumeration + in-memory injection scan + process lineage analysis. "
                    "Full-spectrum detection of Bring Your Own Vulnerable Driver attacks combined with "
                    "memory-resident payload execution — the most advanced EDR evasion technique class.",
        initial_operations=[
            "SYSTEM.INFO",
            "DRIVERS.LIST",
            "PROCESS.LIST",
            "MEMORY.ANALYSIS",
            "NETWORK.CONNECTIONS"
        ],
        adaptive_operations=[
            "PROCESS.PARENT_CHILD",
            "COMMANDLINE.INFO",
            "FILE.HASH",
            "EVENTLOG.RECENT"
        ],
        priority_map={
            "SYSTEM.INFO": 1,
            "DRIVERS.LIST": 2,
            "PROCESS.LIST": 2,
            "MEMORY.ANALYSIS": 2,
            "NETWORK.CONNECTIONS": 2,
            "PROCESS.PARENT_CHILD": 3,
            "COMMANDLINE.INFO": 3,
            "FILE.HASH": 4,
            "EVENTLOG.RECENT": 4
        },
        tags=["byovd", "injection", "kernel", "edr_evasion", "advanced_threat"]
    )
}

class IntentEngine:
    def __init__(self, profiles: dict[str, IntentProfile] | None = None):
        self._profiles = dict(profiles or DEFAULT_INTENT_PROFILES)

    def get_profile(self, intent_id: str) -> IntentProfile | None:
        """Fetch intent configuration profile by ID."""
        return self._profiles.get(intent_id.lower().strip())

    def list_profiles(self) -> list[IntentProfile]:
        """List all registered investigation profiles."""
        return list(self._profiles.values())

    def register_profile(self, profile: IntentProfile) -> None:
        """Register or override an investigation intent profile."""
        self._profiles[profile.intent_id] = profile

    def resolve_initial_operations(self, intent_id: str) -> list[str]:
        """Resolve ordered initial operations for an investigative intent."""
        prof = self.get_profile(intent_id)
        if not prof:
            # Fallback baseline triage if unknown intent specified
            return ["SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "EVENTLOG.RECENT"]
        return list(prof.initial_operations)

    def get_priority(self, intent_id: str, operation: str) -> int:
        """Retrieve priority for an operation under a given intent."""
        prof = self.get_profile(intent_id)
        if prof and operation in prof.priority_map:
            return prof.priority_map[operation]
        return 5
