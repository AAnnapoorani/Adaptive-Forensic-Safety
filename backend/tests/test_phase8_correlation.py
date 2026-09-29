import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.intelligence.correlation_engine import CorrelationEngine

def test_phase8_correlation_engine():
    print("Testing Phase 8: Correlation Engine (Rule-based Forensic Indicators)...")
    engine = CorrelationEngine()

    # 1. Test Positive Match: powershell.exe + External Connection
    evidence_positive = {
        "PROCESS.LIST": [
            {"pid": 4820, "name": "powershell.exe", "username": "SYSTEM"}
        ],
        "NETWORK.CONNECTIONS": [
            {
                "local_address": "192.168.1.100",
                "local_port": 50123,
                "remote_address": "198.51.100.25",  # External routable IP
                "remote_port": 443,
                "status": "ESTABLISHED",
                "pid": 4820,
                "process_name": "powershell.exe",
                "is_external": True
            }
        ]
    }

    matches = engine.evaluate(evidence_positive)
    rule_names = [m.rule_name for m in matches]
    assert "POWERSHELL_NETWORK_ACTIVITY" in rule_names
    ps_match = next(m for m in matches if m.rule_name == "POWERSHELL_NETWORK_ACTIVITY")
    assert ps_match.status_label == "indicator detected"
    assert "PROCESS.PARENT_CHILD" in ps_match.recommended_operations
    assert "COMMANDLINE.INFO" in ps_match.recommended_operations
    print(f"[PASS] Matched rule '{ps_match.rule_name}' with status '{ps_match.status_label}'")

    # 2. Test Benign Scenario (No Match)
    evidence_benign = {
        "PROCESS.LIST": [
            {"pid": 1001, "name": "notepad.exe", "username": "Alice"}
        ],
        "NETWORK.CONNECTIONS": [
            {
                "local_address": "127.0.0.1",
                "local_port": 8000,
                "remote_address": "127.0.0.1",
                "remote_port": 50000,
                "status": "ESTABLISHED",
                "pid": 1001,
                "process_name": "notepad.exe",
                "is_external": False
            }
        ]
    }
    benign_matches = engine.evaluate(evidence_benign)
    assert len(benign_matches) == 0
    print("[PASS] Benign evidence produced 0 matches as expected.")

    # 3. Test Executable File Detection
    evidence_file = {
        "FILES.RECENT": [
            {
                "filename": "payload.ps1",
                "is_executable": True,
                "path": "C:\\demo\\payload.ps1"
            }
        ]
    }
    file_matches = engine.evaluate(evidence_file)
    assert any(m.rule_name == "RECENT_EXECUTABLE_IN_MONITORED_DIR" for m in file_matches)
    print("[PASS] Executable artifact detected and matched correctly.")

if __name__ == "__main__":
    test_phase8_correlation_engine()
    print("\n>>> ALL PHASE 8 CORRELATION ENGINE TESTS PASSED SUCCESSFULLY! <<<\n")
