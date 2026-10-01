from typing import Type
from app.collectors.base import BaseCollector
from app.collectors.system import SystemInfoCollector
from app.collectors.processes import ProcessListCollector
from app.collectors.network import NetworkConnectionsCollector
from app.collectors.dns import DnsInfoCollector
from app.collectors.users import UsersListCollector
from app.collectors.files import FilesRecentCollector, FileHashCollector
from app.collectors.events import EventLogRecentCollector
from app.collectors.commandline import ProcessParentChildCollector, CommandLineInfoCollector
from app.collectors.drivers import DriversListCollector, MemoryAnalysisCollector
from app.collectors.chain_collector import (
    ChainBuildCollector,
    ChainSignCollector,
    ChainVerifyCollector,
    ChainExportCollector
)
from app.collectors.ebpf_linux import LinuxEbpfCollector

COLLECTOR_REGISTRY: dict[str, BaseCollector] = {
    "SYSTEM.INFO": SystemInfoCollector(),
    "PROCESS.LIST": ProcessListCollector(),
    "NETWORK.CONNECTIONS": NetworkConnectionsCollector(),
    "DNS.INFO": DnsInfoCollector(),
    "USERS.LIST": UsersListCollector(),
    "FILES.RECENT": FilesRecentCollector(),
    "FILE.HASH": FileHashCollector(),
    "EVENTLOG.RECENT": EventLogRecentCollector(),
    "PROCESS.PARENT_CHILD": ProcessParentChildCollector(),
    "COMMANDLINE.INFO": CommandLineInfoCollector(),
    # ── Evasion-Aware Collectors (Gap implementations) ──────────────────────
    "DRIVERS.LIST": DriversListCollector(),       # BYOVD detection via ctypes Win32
    "MEMORY.ANALYSIS": MemoryAnalysisCollector(), # In-memory injection detection via VirtualQueryEx
    # ── Integrity 2.0 Collectors ───────────────────────────────────────────
    "CHAIN.BUILD": ChainBuildCollector(),
    "CHAIN.SIGN": ChainSignCollector(),
    "CHAIN.VERIFY": ChainVerifyCollector(),
    "CHAIN.EXPORT": ChainExportCollector(),
    # ── Phase 23: Linux eBPF Kernel Telemetry ──────────────────────────────
    "EBPF.TRACE": LinuxEbpfCollector(),
}


def get_collector(operation: str) -> BaseCollector | None:
    """Retrieve collector instance by JOCKY operation name."""
    return COLLECTOR_REGISTRY.get(operation.upper())

def list_supported_operations() -> list[str]:
    """List all registered forensic operations."""
    return list(COLLECTOR_REGISTRY.keys())
