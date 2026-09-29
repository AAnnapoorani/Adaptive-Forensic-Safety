import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.intelligence.correlation_engine import CorrelationMatchResult
from app.intelligence.escalation_rules import AdaptiveEscalationEngine

def test_phase9_adaptive_escalation():
    print("Testing Phase 9: Adaptive Escalation Engine & Loop Prevention Guards...")
    engine = AdaptiveEscalationEngine(max_rounds=3)

    sample_match = CorrelationMatchResult(
        rule_name="POWERSHELL_NETWORK_ACTIVITY",
        status_label="indicator detected",
        confidence="rule_based",
        description="PowerShell process connected externally",
        recommended_operations=["PROCESS.PARENT_CHILD", "COMMANDLINE.INFO", "FILES.RECENT"]
    )

    # 1. Round 1 -> Round 2 Escalation
    executed_r1 = {"SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "DNS.INFO", "EVENTLOG.RECENT"}
    triggered_rules = set()

    decision = engine.evaluate_escalation(
        current_round=1,
        matches=[sample_match],
        executed_operations=executed_r1,
        triggered_rules=triggered_rules
    )

    assert decision.should_escalate is True
    assert decision.round_number == 2
    assert decision.trigger_rule == "POWERSHELL_NETWORK_ACTIVITY"
    assert "PROCESS.PARENT_CHILD" in decision.new_operations
    assert "COMMANDLINE.INFO" in decision.new_operations
    assert "FILES.RECENT" in decision.new_operations
    print(f"[PASS] Adaptive escalation triggered for Round 2: {decision.new_operations}")

    # 2. Pruning already executed operations
    # Suppose FILES.RECENT was already run
    executed_with_files = executed_r1 | {"FILES.RECENT"}
    decision2 = engine.evaluate_escalation(
        current_round=1,
        matches=[sample_match],
        executed_operations=executed_with_files,
        triggered_rules=triggered_rules
    )
    assert decision2.should_escalate is True
    assert "FILES.RECENT" not in decision2.new_operations
    assert "PROCESS.PARENT_CHILD" in decision2.new_operations
    print(f"[PASS] Already-executed operation pruned: {decision2.new_operations}")

    # 3. Duplicate Rule Guard
    triggered_rules.add("POWERSHELL_NETWORK_ACTIVITY")
    decision3 = engine.evaluate_escalation(
        current_round=2,
        matches=[sample_match],
        executed_operations=executed_with_files,
        triggered_rules=triggered_rules
    )
    assert decision3.should_escalate is False
    print(f"[PASS] Duplicate rule re-trigger successfully blocked: {decision3.reason}")

    # 4. Max Rounds Loop Prevention Guard
    decision_max = engine.evaluate_escalation(
        current_round=3,
        matches=[sample_match],
        executed_operations=executed_r1,
        triggered_rules=set()
    )
    assert decision_max.should_escalate is False
    assert "ceiling" in decision_max.reason.lower()
    print(f"[PASS] MAX_ROUNDS = 3 loop prevention guard enforced: {decision_max.reason}")

if __name__ == "__main__":
    test_phase9_adaptive_escalation()
    print("\n>>> ALL PHASE 9 ADAPTIVE ESCALATION TESTS PASSED SUCCESSFULLY! <<<\n")
