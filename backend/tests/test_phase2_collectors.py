import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.collectors.registry import get_collector, list_supported_operations
from app.core.config import settings

def test_phase2_collectors():
    print("Testing all Phase 2 Forensic Collectors...")
    
    # Check operations registration
    ops = list_supported_operations()
    expected_ops = [
        "SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "DNS.INFO",
        "USERS.LIST", "FILES.RECENT", "FILE.HASH", "EVENTLOG.RECENT",
        "PROCESS.PARENT_CHILD", "COMMANDLINE.INFO"
    ]
    for op in expected_ops:
        assert op in ops, f"Operation {op} missing from registry"
    print(f"[PASS] All {len(expected_ops)} operations registered in registry.")

    # 1. SYSTEM.INFO
    c = get_collector("SYSTEM.INFO")
    res = c.collect()
    assert res.status == "SUCCESS"
    assert "operating_system" in res.data
    assert "hostname" in res.data
    print(f"[PASS] SYSTEM.INFO: OS={res.data['operating_system']}, Host={res.data['hostname']}")

    # 2. PROCESS.LIST
    c = get_collector("PROCESS.LIST")
    res = c.collect({"limit": 10})
    assert res.status == "SUCCESS"
    assert len(res.data) > 0
    assert "pid" in res.data[0]
    print(f"[PASS] PROCESS.LIST: Captured {len(res.data)} processes (Sample: PID {res.data[0]['pid']} - {res.data[0]['name']})")

    # 3. NETWORK.CONNECTIONS
    c = get_collector("NETWORK.CONNECTIONS")
    res = c.collect()
    assert res.status in ["SUCCESS", "PARTIALLY_COMPLETED"]
    print(f"[PASS] NETWORK.CONNECTIONS: Found {len(res.data)} sockets")

    # 4. DNS.INFO
    c = get_collector("DNS.INFO")
    res = c.collect()
    assert res.status in ["SUCCESS", "NOT_AVAILABLE"]
    print(f"[PASS] DNS.INFO: Status={res.status}, Servers={len(res.data.get('dns_servers', []))}")

    # 5. USERS.LIST
    c = get_collector("USERS.LIST")
    res = c.collect()
    assert res.status == "SUCCESS"
    print(f"[PASS] USERS.LIST: Found {len(res.data['local_accounts'])} local accounts / sessions")

    # 6. FILES.RECENT
    c = get_collector("FILES.RECENT")
    res = c.collect()
    assert res.status == "SUCCESS"
    assert len(res.data) >= 1
    print(f"[PASS] FILES.RECENT: Monitored {len(res.data)} files in safe directory")

    # 7. FILE.HASH
    test_file = settings.SAFE_SCAN_DIR / "hash_target.txt"
    test_file.write_text("JOCKY Forensic Hash Target Verification Test")
    c = get_collector("FILE.HASH")
    res = c.collect({"path": str(test_file)})
    assert res.status == "SUCCESS"
    assert res.data["sha256"]
    print(f"[PASS] FILE.HASH: Target SHA-256 = {res.data['sha256']}")

    # 8. EVENTLOG.RECENT
    c = get_collector("EVENTLOG.RECENT")
    res = c.collect({"limit": 5})
    assert res.status in ["SUCCESS", "PARTIALLY_COMPLETED"]
    print(f"[PASS] EVENTLOG.RECENT: Status={res.status}, Entries={len(res.data)}")

    # 9. PROCESS.PARENT_CHILD
    c = get_collector("PROCESS.PARENT_CHILD")
    res = c.collect()
    assert res.status == "SUCCESS"
    assert len(res.data) > 0
    print(f"[PASS] PROCESS.PARENT_CHILD: Mapped {len(res.data)} parent-child relationships")

    # 10. COMMANDLINE.INFO
    c = get_collector("COMMANDLINE.INFO")
    res = c.collect()
    assert res.status == "SUCCESS"
    print(f"[PASS] COMMANDLINE.INFO: Captured {len(res.data)} process command-lines")

if __name__ == "__main__":
    test_phase2_collectors()
    print("\n>>> ALL PHASE 2 FORENSIC COLLECTOR TESTS PASSED SUCCESSFULLY! <<<\n")
