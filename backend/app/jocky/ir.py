from dataclasses import dataclass, field, asdict
from typing import Any
from app.jocky.ast import (
    ProgramNode,
    InvestigateNode,
    TargetNode,
    RoundLimitNode,
    OptionsNode,
    OperationNode,
    FileHashNode,
    CaseNode,
    ChainNode,
    SignNode,
    VerifyNode,
    ExportNode,
)

@dataclass
class IRInstruction:
    kind: str  # INVESTIGATION, COLLECTION, SYNTHESIS, INTEGRITY, CONFIG
    operation: str  # INVESTIGATE, PROCESS_LIST, CHAIN_BUILD, etc.
    parameters: dict[str, Any] = field(default_factory=dict)
    source_line: int = 1

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind, "operation": self.operation}
        if self.parameters:
            d["parameters"] = self.parameters
        return d

@dataclass
class IntermediateRepresentation:
    intent: str | None = None
    target: str | None = None
    round_limit: int | None = None
    options: dict[str, Any] = field(default_factory=dict)
    case_id: str | None = None
    operations: list[str] = field(default_factory=list)
    instructions: list[IRInstruction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "instructions": [ins.to_dict() for ins in self.instructions]
        }
        if self.intent is not None:
            result["intent"] = self.intent
        if self.target is not None:
            result["target"] = self.target
        if self.round_limit is not None:
            result["round_limit"] = self.round_limit
        if self.options:
            result["options"] = self.options
        if self.case_id is not None:
            result["case_id"] = self.case_id
        if self.operations:
            result["operations"] = self.operations
        return result

def ast_to_ir(program: ProgramNode) -> IntermediateRepresentation:
    """Transform high-level AST into platform-independent IR representation."""
    from app.intelligence.intent_engine import IntentEngine

    ir_instructions: list[IRInstruction] = []
    primary_intent: str | None = None
    target_machine: str | None = None
    round_limit: int | None = None
    collected_options: dict[str, Any] = {}
    case_id: str | None = None
    resolved_operations: list[str] = []

    intent_engine = IntentEngine()

    for stmt in program.statements:
        if isinstance(stmt, InvestigateNode):
            primary_intent = stmt.intent
            resolved = intent_engine.resolve_initial_operations(stmt.intent)
            for op in resolved:
                if op not in resolved_operations:
                    resolved_operations.append(op)

            ir_instructions.append(IRInstruction(
                kind="INVESTIGATION",
                operation="INVESTIGATE",
                parameters={"intent": stmt.intent},
                source_line=stmt.line
            ))
        elif isinstance(stmt, TargetNode):
            target_machine = stmt.target
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="TARGET_ENDPOINT",
                parameters={"target": stmt.target},
                source_line=stmt.line
            ))
        elif isinstance(stmt, RoundLimitNode):
            round_limit = stmt.limit
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="SET_ROUND_LIMIT",
                parameters={"round_limit": stmt.limit},
                source_line=stmt.line
            ))
        elif isinstance(stmt, OptionsNode):
            collected_options.update(stmt.options)
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="SET_OPTIONS",
                parameters=stmt.options,
                source_line=stmt.line
            ))
        elif isinstance(stmt, CaseNode):
            case_id = stmt.case_id
            ir_instructions.append(IRInstruction(
                kind="INVESTIGATION",
                operation="CASE_INIT",
                parameters={"case_id": stmt.case_id},
                source_line=stmt.line
            ))
        elif isinstance(stmt, FileHashNode):
            if "FILE.HASH" not in resolved_operations:
                resolved_operations.append("FILE.HASH")
            ir_instructions.append(IRInstruction(
                kind="COLLECTION",
                operation="FILE_HASH",
                parameters={"path": stmt.path},
                source_line=stmt.line
            ))
        elif isinstance(stmt, ChainNode):
            if "CHAIN.BUILD" not in resolved_operations:
                resolved_operations.append("CHAIN.BUILD")
            ir_instructions.append(IRInstruction(
                kind="INTEGRITY",
                operation="CHAIN_BUILD",
                parameters={"target": stmt.target},
                source_line=stmt.line
            ))
        elif isinstance(stmt, SignNode):
            if "CHAIN.SIGN" not in resolved_operations:
                resolved_operations.append("CHAIN.SIGN")
            ir_instructions.append(IRInstruction(
                kind="INTEGRITY",
                operation="CHAIN_SIGN",
                parameters={"algorithm": stmt.algorithm},
                source_line=stmt.line
            ))
        elif isinstance(stmt, VerifyNode):
            if "CHAIN.VERIFY" not in resolved_operations:
                resolved_operations.append("CHAIN.VERIFY")
            ir_instructions.append(IRInstruction(
                kind="INTEGRITY",
                operation="CHAIN_VERIFY",
                parameters={"target": stmt.target},
                source_line=stmt.line
            ))
        elif isinstance(stmt, ExportNode):
            if "CHAIN.EXPORT" not in resolved_operations:
                resolved_operations.append("CHAIN.EXPORT")
            ir_instructions.append(IRInstruction(
                kind="INTEGRITY",
                operation="CHAIN_EXPORT",
                parameters={"target": stmt.target},
                source_line=stmt.line
            ))
        elif isinstance(stmt, OperationNode):
            if stmt.operation not in resolved_operations:
                resolved_operations.append(stmt.operation)
            op_norm = stmt.operation.replace(".", "_")
            if op_norm.startswith("CHAIN_"):
                kind = "INTEGRITY"
            elif op_norm in ("TIMELINE_CREATE", "REPORT_GENERATE"):
                kind = "SYNTHESIS"
            else:
                kind = "COLLECTION"
            ir_instructions.append(IRInstruction(
                kind=kind,
                operation=op_norm,
                parameters=stmt.params,
                source_line=stmt.line
            ))

    if not primary_intent and resolved_operations:
        primary_intent = "suspicious_network_activity"

    return IntermediateRepresentation(
        intent=primary_intent,
        target=target_machine,
        round_limit=round_limit,
        options=collected_options,
        case_id=case_id,
        operations=resolved_operations,
        instructions=ir_instructions
    )
