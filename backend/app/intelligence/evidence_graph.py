from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class EvidenceNode:
    id: str
    operation: str
    label: str
    category: str  # SYSTEM, PROCESS, NETWORK, STORAGE, AUDIT, CORRELATION, SYNTHESIS
    required: bool = True
    status: str = "PLANNED"  # PLANNED, COLLECTING, COLLECTED, FAILED, EXPANDED
    round_number: int = 1
    reason: str = "Initial investigative requirement"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class EvidenceEdge:
    source: str
    target: str
    relationship: str  # PRECEDES, CORRELATES_WITH, FEEDS_TIMELINE, EXPANDS_TO

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

CATEGORY_MAP = {
    "SYSTEM.INFO": ("System Metadata", "SYSTEM"),
    "PROCESS.LIST": ("Process Tree & Table", "PROCESS"),
    "NETWORK.CONNECTIONS": ("Socket Telemetry", "NETWORK"),
    "DNS.INFO": ("DNS Resolvers & Cache", "NETWORK"),
    "USERS.LIST": ("User Accounts & Sessions", "AUDIT"),
    "FILES.RECENT": ("Monitored Directory Files", "STORAGE"),
    "FILE.HASH": ("File Cryptographic Hash", "STORAGE"),
    "EVENTLOG.RECENT": ("System Event Logs", "AUDIT"),
    "PROCESS.PARENT_CHILD": ("Process Lineage Hierarchy", "PROCESS"),
    "COMMANDLINE.INFO": ("Process Execution Arguments", "PROCESS"),
    "TIMELINE.CREATE": ("Forensic Timeline Synthesis", "SYNTHESIS"),
    "REPORT.GENERATE": ("Forensic Investigation Report", "SYNTHESIS"),
    "DRIVERS.LIST": ("Kernel Driver Catalog & BYOVD", "KERNEL"),
    "MEMORY.ANALYSIS": ("In-Memory VAD Injection Scan", "MEMORY"),
    # ── Integrity 2.0 ────────────────────────────────────────────────────────
    "CHAIN.BUILD": ("Hash Chain Assembly", "INTEGRITY"),
    "CHAIN.SIGN": ("Ed25519 Chain Tip Signing", "INTEGRITY"),
    "CHAIN.VERIFY": ("7-Pass Cryptographic Verification", "INTEGRITY"),
    "CHAIN.EXPORT": ("Portable Forensic Packaging", "INTEGRITY"),
}


class EvidenceRequirementGraph:
    def __init__(self, intent: str = "custom_investigation"):
        self.intent = intent
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: list[EvidenceEdge] = []

    def add_node(self, node: EvidenceNode) -> None:
        self.nodes[node.id] = node

    def _reaches(self, start: str, target: str) -> bool:
        visited = set()
        queue = [start]
        while queue:
            curr = queue.pop(0)
            if curr == target:
                return True
            if curr not in visited:
                visited.add(curr)
                for e in self.edges:
                    if e.relationship in ("PRECEDES", "EXPANDS_TO") and e.source == curr:
                        if e.target not in visited:
                            queue.append(e.target)
        return False

    def add_edge(self, source_id: str, target_id: str, relationship: str = "PRECEDES") -> None:
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        if source_id == target_id:
            raise ValueError(f"Cycle detected: Self-loop edge '{source_id}' -> '{target_id}' is not allowed in DAG.")
        if relationship in ("PRECEDES", "EXPANDS_TO") and self._reaches(target_id, source_id):
            raise ValueError(f"Cycle detected in Evidence Requirement Graph: adding edge '{source_id}' -> '{target_id}' introduces a cycle.")
        for e in self.edges:
            if e.source == source_id and e.target == target_id and e.relationship == relationship:
                return
        self.edges.append(EvidenceEdge(source=source_id, target=target_id, relationship=relationship))

    def has_cycle(self) -> bool:
        visited: dict[str, int] = {nid: 0 for nid in self.nodes}
        def dfs(node: str) -> bool:
            visited[node] = 1
            for e in self.edges:
                if e.relationship in ("PRECEDES", "EXPANDS_TO") and e.source == node:
                    if visited.get(e.target) == 1:
                        return True
                    if visited.get(e.target) == 0 and dfs(e.target):
                        return True
            visited[node] = 2
            return False
        for nid in self.nodes:
            if visited[nid] == 0:
                if dfs(nid):
                    return True
        return False

    def topological_sort(self) -> list[EvidenceNode]:
        in_degree = {nid: 0 for nid in self.nodes}
        for e in self.edges:
            if e.relationship in ("PRECEDES", "EXPANDS_TO") and e.target in in_degree:
                in_degree[e.target] += 1
        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        sorted_nodes = []
        while queue:
            curr = queue.pop(0)
            sorted_nodes.append(self.nodes[curr])
            for e in self.edges:
                if e.relationship in ("PRECEDES", "EXPANDS_TO") and e.source == curr:
                    if e.target in in_degree:
                        in_degree[e.target] -= 1
                        if in_degree[e.target] == 0:
                            queue.append(e.target)
        if len(sorted_nodes) < len(self.nodes):
            for nid, node in self.nodes.items():
                if node not in sorted_nodes:
                    sorted_nodes.append(node)
        return sorted_nodes

    def get_completed_operations(self) -> list[str]:
        return [n.operation for n in self.nodes.values() if n.status == "COLLECTED"]

    def get_newly_required_operations(self, round_number: int | None = None) -> list[str]:
        return [
            n.operation for n in self.nodes.values()
            if (round_number is None or n.round_number == round_number) and n.status == "PLANNED"
        ]

    def update_node_status(self, node_id: str, status: str) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].status = status

    def get_node_by_operation(self, operation: str) -> EvidenceNode | None:
        for node in self.nodes.values():
            if node.operation == operation:
                return node
        return None

    def expand_with_operations(
        self,
        new_operations: list[str],
        trigger_rule: str,
        round_number: int
    ) -> list[EvidenceNode]:
        """Dynamically expand evidence graph with adaptive operations."""
        added_nodes = []
        parent_node_id = f"node_correlation_r{round_number - 1}"
        if parent_node_id not in self.nodes:
            parent_node_id = "node_process_list" if "node_process_list" in self.nodes else list(self.nodes.keys())[0]

        for op in new_operations:
            node_id = f"node_{op.lower().replace('.', '_')}"
            if node_id in self.nodes:
                continue

            label, category = CATEGORY_MAP.get(op, (op, "COLLECTION"))
            node = EvidenceNode(
                id=node_id,
                operation=op,
                label=label,
                category=category,
                required=True,
                status="PLANNED",
                round_number=round_number,
                reason=f"Adaptive expansion triggered by {trigger_rule}"
            )
            self.add_node(node)
            self.add_edge(parent_node_id, node_id, relationship="EXPANDS_TO")

            # Logical dependency relationships
            if op == "PROCESS.PARENT_CHILD" and "node_process_list" in self.nodes:
                self.add_edge("node_process_list", node_id, relationship="PRECEDES")
            elif op == "COMMANDLINE.INFO" and "node_process_list" in self.nodes:
                self.add_edge("node_process_list", node_id, relationship="PRECEDES")
            elif op == "FILE.HASH" and "node_files_recent" in self.nodes:
                self.add_edge("node_files_recent", node_id, relationship="PRECEDES")

            added_nodes.append(node)

        return added_nodes

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "completed_operations": self.get_completed_operations(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }

def build_evidence_graph_for_intent(intent: str, operations: list[str]) -> EvidenceRequirementGraph:
    """Build the initial Evidence Requirement Graph from intent and required operations."""
    graph = EvidenceRequirementGraph(intent=intent)

    # 1. Create nodes for all initial operations
    op_node_ids = {}
    for op in operations:
        node_id = f"node_{op.lower().replace('.', '_')}"
        label, category = CATEGORY_MAP.get(op, (op, "COLLECTION"))
        node = EvidenceNode(
            id=node_id,
            operation=op,
            label=label,
            category=category,
            required=True,
            status="PLANNED",
            round_number=1,
            reason="Initial investigative requirement"
        )
        graph.add_node(node)
        op_node_ids[op] = node_id

    # 2. Add structural / logical evidence relationship edges
    # SYSTEM.INFO precedes PROCESS.LIST and NETWORK.CONNECTIONS
    if "SYSTEM.INFO" in op_node_ids:
        sys_id = op_node_ids["SYSTEM.INFO"]
        if "PROCESS.LIST" in op_node_ids:
            graph.add_edge(sys_id, op_node_ids["PROCESS.LIST"], "PRECEDES")
        if "NETWORK.CONNECTIONS" in op_node_ids:
            graph.add_edge(sys_id, op_node_ids["NETWORK.CONNECTIONS"], "PRECEDES")

    # PROCESS.LIST correlates with NETWORK.CONNECTIONS
    if "PROCESS.LIST" in op_node_ids and "NETWORK.CONNECTIONS" in op_node_ids:
        graph.add_edge(op_node_ids["PROCESS.LIST"], op_node_ids["NETWORK.CONNECTIONS"], "CORRELATES_WITH")

    # NETWORK.CONNECTIONS correlates with DNS.INFO
    if "NETWORK.CONNECTIONS" in op_node_ids and "DNS.INFO" in op_node_ids:
        graph.add_edge(op_node_ids["NETWORK.CONNECTIONS"], op_node_ids["DNS.INFO"], "CORRELATES_WITH")

    # PROCESS.LIST correlates with EVENTLOG.RECENT
    if "PROCESS.LIST" in op_node_ids and "EVENTLOG.RECENT" in op_node_ids:
        graph.add_edge(op_node_ids["PROCESS.LIST"], op_node_ids["EVENTLOG.RECENT"], "CORRELATES_WITH")

    # PROCESS.LIST correlates with FILES.RECENT
    if "PROCESS.LIST" in op_node_ids and "FILES.RECENT" in op_node_ids:
        graph.add_edge(op_node_ids["PROCESS.LIST"], op_node_ids["FILES.RECENT"], "CORRELATES_WITH")

    return graph
