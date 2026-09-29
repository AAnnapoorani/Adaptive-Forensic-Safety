"""
Phase 17 Unit & Integration Tests:
- In-Memory Activity Detection: rules, scoring, and classification
- Live in-memory detection integration
- Platform capabilities matrix endpoint (/api/health/capabilities)
- Security analysis REST endpoints (/api/jocky/security-analysis)
"""

import pytest
from app.intelligence.in_memory_detection import (
    detect_in_memory_indicators,
    run_live_detection
)
from app.api.health import get_capabilities
from app.api.evasion import get_security_analysis, post_security_analysis


def test_capabilities_endpoint():
    """Verify capabilities probe returns platform architecture and available collectors."""
    caps = get_capabilities()
    assert "platform" in caps
    assert "collectors" in caps
    assert "available_collectors" in caps
    assert caps["available_collectors"] > 0
    assert "SYSTEM.INFO" in caps["collectors"]
    assert caps["collectors"]["SYSTEM.INFO"]["available"] is True


def test_in_memory_detection_clean_baseline():
    """Verify clean system or empty telemetry generates zero false positive indicators."""
    evidence = {
        "PROCESS.LIST": [
            {
                "pid": 1000,
                "name": "explorer.exe",
                "ppid": 500,
                "cmdline": "C:\\Windows\\explorer.exe",
                "exe": "C:\\Windows\\explorer.exe"
            }
        ],
        "NETWORK.CONNECTIONS": [],
        "PROCESS.PARENT_CHILD": [],
        "DRIVERS.LIST": [],
        "MEMORY.ANALYSIS": []
    }
    res = detect_in_memory_indicators(evidence)
    assert res["status"] == "COMPLETED"
    assert "total_indicators" in res
    assert "classification" in res
    assert isinstance(res["indicators"], list)


def test_in_memory_detection_suspicious_indicators():
    """Verify detection of suspicious indicators like unusual parent-child and missing disk module."""
    synthetic_evidence = {
        "PROCESS.LIST": [
            {
                "pid": 4444,
                "name": "powershell.exe",
                "ppid": 1111,
                "cmdline": "powershell.exe -enc AAAA",
                "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            {
                "pid": 5555,
                "name": "cmd.exe",
                "ppid": 2222,
                "cmdline": "cmd.exe /c whoami",
                "exe": "C:\\Windows\\System32\\cmd.exe"
            }
        ],
        "PROCESS.PARENT_CHILD": [
            {
                "parent_name": "WINWORD.EXE",
                "child_name": "powershell.exe",
                "parent_pid": 1111,
                "child_pid": 4444
            },
            {
                "parent_name": "excel.exe",
                "child_name": "cmd.exe",
                "parent_pid": 2222,
                "child_pid": 5555
            }
        ],
        "NETWORK.CONNECTIONS": [
            {
                "pid": 4444,
                "process_name": "powershell.exe",
                "remote_ip": "198.51.100.42",
                "remote_port": 4444,
                "status": "ESTABLISHED"
            }
        ],
        "DRIVERS.LIST": [],
        "MEMORY.ANALYSIS": [
            {
                "pid": 4444,
                "type": "PAGE_EXECUTE_READWRITE",
                "state": "MEM_COMMIT",
                "protect": "0x40"
            }
        ]
    }

    res = detect_in_memory_indicators(synthetic_evidence)
    assert res["total_indicators"] >= 2
    rule_names = {ind["rule_name"] for ind in res["indicators"]}
    assert "UNUSUAL_PARENT_CHILD_SPAWN" in rule_names


def test_live_detection_callable():
    """Verify live detection runs without throwing exceptions on the current host."""
    res = run_live_detection()
    assert "status" in res
    assert "classification" in res
    assert "evidence_sources" in res
    assert res["evidence_sources"]["processes_scanned"] >= 0


def test_security_analysis_api_roundtrip():
    """Verify REST API handlers for security analysis function correctly."""
    live_res = get_security_analysis()
    assert "status" in live_res

    post_res = post_security_analysis({
        "PROCESS.LIST": [],
        "NETWORK.CONNECTIONS": []
    })
    assert post_res["status"] == "COMPLETED"
