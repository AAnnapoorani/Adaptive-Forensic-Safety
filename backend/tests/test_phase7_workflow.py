import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.intelligence.evidence_graph import build_evidence_graph_for_intent
from app.intelligence.workflow_planner import WorkflowCompiler

def test_phase7_workflow_compiler():
    print("Testing Phase 7: Workflow Compiler (Graph to Executable Workflow)...")

    # 1. Build Initial Graph
    intent = "suspicious_network_activity"
    initial_ops = ["SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "DNS.INFO", "EVENTLOG.RECENT"]
    graph = build_evidence_graph_for_intent(intent, initial_ops)

    # 2. Compile to Round 1 Executable Workflow
    workflow_r1 = WorkflowCompiler.compile(graph, investigation_id="INV-001", round_number=1)
    assert len(workflow_r1.steps) == 5
    assert workflow_r1.steps[0].operation == "SYSTEM.INFO"
    assert workflow_r1.steps[0].priority == 1
    assert workflow_r1.steps[-1].operation == "EVENTLOG.RECENT"
    assert workflow_r1.steps[-1].priority == 3
    print(f"[PASS] Round 1 workflow compiled in correct priority order:")
    for step in workflow_r1.steps:
        print(f"       -> {step.step_id}: {step.operation} (Priority {step.priority})")

    # 3. Simulate Round 1 Execution & Loop Prevention Guard
    executed = {"SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "DNS.INFO", "EVENTLOG.RECENT"}

    # 4. Expand Graph with Adaptive Operations for Round 2
    graph.expand_with_operations(
        new_operations=["PROCESS.PARENT_CHILD", "COMMANDLINE.INFO", "PROCESS.LIST"],  # Note PROCESS.LIST is already executed
        trigger_rule="POWERSHELL_NETWORK_ACTIVITY",
        round_number=2
    )

    # 5. Compile Round 2 Workflow
    workflow_r2 = WorkflowCompiler.compile(
        graph,
        investigation_id="INV-001",
        round_number=2,
        already_executed_ops=executed
    )

    # PROCESS.LIST should NOT be in round 2 because it was already executed
    op_names_r2 = [s.operation for s in workflow_r2.steps]
    assert "PROCESS.LIST" not in op_names_r2
    assert "PROCESS.PARENT_CHILD" in op_names_r2
    assert "COMMANDLINE.INFO" in op_names_r2
    assert len(workflow_r2.steps) == 2
    print(f"[PASS] Round 2 adaptive workflow compiled with loop prevention:")
    for step in workflow_r2.steps:
        print(f"       -> {step.step_id}: {step.operation} (Reason: {step.reason})")

if __name__ == "__main__":
    test_phase7_workflow_compiler()
    print("\n>>> ALL PHASE 7 WORKFLOW COMPILER TESTS PASSED SUCCESSFULLY! <<<\n")
