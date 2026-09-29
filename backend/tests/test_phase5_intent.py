import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.intelligence.intent_engine import IntentEngine, IntentProfile

def test_phase5_intent_engine():
    print("Testing Phase 5: Intent Engine (Configurable Semantic Profiles)...")
    engine = IntentEngine()

    # 1. Test suspicious_network_activity
    p1 = engine.get_profile("suspicious_network_activity")
    assert p1 is not None
    assert "NETWORK.CONNECTIONS" in p1.initial_operations
    assert "DNS.INFO" in p1.initial_operations
    print(f"[PASS] Resolved intent '{p1.intent_id}': {p1.initial_operations}")

    # 2. Test possible_malware_execution
    p2 = engine.get_profile("possible_malware_execution")
    assert p2 is not None
    assert "FILES.RECENT" in p2.initial_operations
    print(f"[PASS] Resolved intent '{p2.intent_id}': {p2.initial_operations}")

    # 3. Test system_compromise
    p3 = engine.get_profile("system_compromise")
    assert p3 is not None
    assert "USERS.LIST" in p3.initial_operations
    print(f"[PASS] Resolved intent '{p3.intent_id}': {p3.initial_operations}")

    # 4. Test Custom Profile Registration
    custom_prof = IntentProfile(
        intent_id="custom_ransomware_triage",
        display_name="Ransomware Triage",
        description="Custom triage for rapid extension identification",
        initial_operations=["SYSTEM.INFO", "FILES.RECENT", "PROCESS.LIST"],
        priority_map={"SYSTEM.INFO": 1, "FILES.RECENT": 2, "PROCESS.LIST": 2}
    )
    engine.register_profile(custom_prof)
    resolved = engine.resolve_initial_operations("custom_ransomware_triage")
    assert resolved == ["SYSTEM.INFO", "FILES.RECENT", "PROCESS.LIST"]
    print(f"[PASS] Custom intent profile registered and resolved: {resolved}")

    # 5. Test Fallback for Unknown Intent
    fallback = engine.resolve_initial_operations("completely_unknown_intent")
    assert len(fallback) > 0
    print(f"[PASS] Fallback baseline for unknown intent: {fallback}")

if __name__ == "__main__":
    test_phase5_intent_engine()
    print("\n>>> ALL PHASE 5 INTENT ENGINE TESTS PASSED SUCCESSFULLY! <<<\n")
