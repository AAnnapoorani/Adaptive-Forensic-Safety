from dataclasses import dataclass, field, asdict
from typing import Any
from app.intelligence.evidence_graph import EvidenceRequirementGraph

@dataclass
class PlannedStep:
    step_id: str
    operation: str
    priority: int
    dependencies: list[str] = field(default_factory=list)
    round_number: int = 1
    reason: str = "Investigation requirement"
    status: str = "PENDING"
    start_time: str | None = None
    end_time: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class ExecutableWorkflow:
    investigation_id: str
    round_number: int
    steps: list[PlannedStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "round_number": self.round_number,
            "total_steps": len(self.steps),
            "steps": [s.to_dict() for s in self.steps]
        }

DEFAULT_PRIORITY_ORDER = {
    "SYSTEM.INFO": 1,
    "PROCESS.LIST": 2,
    "NETWORK.CONNECTIONS": 2,
    "DNS.INFO": 2,
    "USERS.LIST": 2,
    "DRIVERS.LIST": 2,
    "FILES.RECENT": 3,
    "EVENTLOG.RECENT": 3,
    "MEMORY.ANALYSIS": 3,
    "PROCESS.PARENT_CHILD": 4,
    "COMMANDLINE.INFO": 4,
    "FILE.HASH": 4,
    "TIMELINE.CREATE": 5,
    "REPORT.GENERATE": 6,
    # ── Integrity 2.0 (Culmination stages) ────────────────────────────────────
    "CHAIN.BUILD": 7,
    "CHAIN.SIGN": 8,
    "CHAIN.VERIFY": 9,
    "CHAIN.EXPORT": 10
}


class WorkflowCompiler:
    @staticmethod
    def compile(
        graph: EvidenceRequirementGraph,
        investigation_id: str = "INV-PREVIEW",
        round_number: int = 1,
        priority_map: dict[str, int] | None = None,
        already_executed_ops: set[str] | None = None
    ) -> ExecutableWorkflow:
        """Compile an Evidence Requirement Graph into an ordered, executable workflow for the specified round."""
        priorities = dict(priority_map or DEFAULT_PRIORITY_ORDER)
        executed = already_executed_ops or set()

        # Filter nodes relevant for this round or pending execution
        candidate_nodes = [
            node for node in graph.nodes.values()
            if node.round_number == round_number and node.operation not in executed
        ]

        # Extract dependency relationships from graph edges
        dep_map: dict[str, list[str]] = {node.operation: [] for node in candidate_nodes}
        for edge in graph.edges:
            if edge.relationship == "PRECEDES":
                src_node = graph.nodes.get(edge.source)
                tgt_node = graph.nodes.get(edge.target)
                if src_node and tgt_node and tgt_node.operation in dep_map:
                    dep_map[tgt_node.operation].append(src_node.operation)

        # Sort candidate nodes by priority (ascending) and then by operation name
        candidate_nodes.sort(
            key=lambda n: (priorities.get(n.operation, 10), n.operation)
        )

        steps = []
        for idx, node in enumerate(candidate_nodes, start=1):
            step = PlannedStep(
                step_id=f"STEP-R{round_number}-{idx:02d}",
                operation=node.operation,
                priority=priorities.get(node.operation, 5),
                dependencies=dep_map.get(node.operation, []),
                round_number=round_number,
                reason=node.reason,
                status="PENDING"
            )
            steps.append(step)

        return ExecutableWorkflow(
            investigation_id=investigation_id,
            round_number=round_number,
            steps=steps
        )
