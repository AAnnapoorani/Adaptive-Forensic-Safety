import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.intelligence.evidence_graph import build_evidence_graph_for_intent

def test_phase6_evidence_graph():
    print("Testing Phase 6: Evidence Requirement Graph (DAG Construction & Expansion)...")

    # 1. Build Initial Evidence Requirement Graph
    intent = "suspicious_network_activity"
    initial_ops = ["SYSTEM.INFO", "PROCESS.LIST", "NETWORK.CONNECTIONS", "DNS.INFO", "EVENTLOG.RECENT"]
    graph = build_evidence_graph_for_intent(intent, initial_ops)

    assert len(graph.nodes) == 5
    assert "node_system_info" in graph.nodes
    assert "node_process_list" in graph.nodes
    assert "node_network_connections" in graph.nodes
    assert len(graph.edges) >= 3

    # Check edges
    relationships = [(e.source, e.target, e.relationship) for e in graph.edges]
    assert ("node_system_info", "node_process_list", "PRECEDES") in relationships
    assert ("node_process_list", "node_network_connections", "CORRELATES_WITH") in relationships
    print(f"[PASS] Initial graph constructed: {len(graph.nodes)} nodes, {len(graph.edges)} edges.")

    # 2. Test Dynamic Adaptive Expansion
    adaptive_ops = ["PROCESS.PARENT_CHILD", "COMMANDLINE.INFO"]
    added_nodes = graph.expand_with_operations(
        new_operations=adaptive_ops,
        trigger_rule="POWERSHELL_NETWORK_ACTIVITY",
        round_number=2
    )

    assert len(added_nodes) == 2
    assert "node_process_parent_child" in graph.nodes
    assert "node_commandline_info" in graph.nodes
    assert graph.nodes["node_process_parent_child"].round_number == 2
    assert graph.nodes["node_process_parent_child"].reason.startswith("Adaptive expansion")
    
    # Check expands_to edges
    expands_edges = [e for e in graph.edges if e.relationship == "EXPANDS_TO"]
    assert len(expands_edges) == 2
    print(f"[PASS] Dynamic graph expansion verified: Graph now has {len(graph.nodes)} nodes and {len(graph.edges)} edges.")

    # 3. Test Serialization
    serialized = graph.to_dict()
    assert "nodes" in serialized
    assert "edges" in serialized
    assert serialized["total_nodes"] == 7
    print(f"[PASS] Graph successfully serialized to JSON-ready dict.")

if __name__ == "__main__":
    test_phase6_evidence_graph()
    print("\n>>> ALL PHASE 6 EVIDENCE REQUIREMENT GRAPH TESTS PASSED SUCCESSFULLY! <<<\n")
