from dataclasses import dataclass, field, asdict
from typing import Any
from app.jocky.ast import (
    ProgramNode,
    InvestigateNode,
    OperationNode,
    FileHashNode,
    CaseNode,
    ChainNode,
    SignNode,
    VerifyNode,
    ExportNode,
    TargetNode,
    RoundLimitNode,
    OptionsNode,
)

@dataclass
class IRInstruction:
    kind: str  # INVESTIGATION, COLLECTION, SYNTHESIS, INTEGRITY, CONFIG
    operation: str  # INVESTIGATE, PROCESS_LIST, CHAIN_BUILD, etc.
    parameters: dict[str, Any] = field(default_factory=dict)
    source_line: int = 1

    def to_dict(self) -> dict[str, Any]:
        d = {"kind": self.kind, "operation": self.operation}
        if self.parameters:
            d["parameters"] = self.parameters
        return d

@dataclass
class IntermediateRepresentation:
    intent: str | None = None
    case_id: str | None = None
    target_id: str | None = None
    round_limit: int | None = None
    options: dict[str, Any] = field(default_factory=dict)
    operations: list[str] = field(default_factory=list)
    instructions: list[IRInstruction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "instructions": [ins.to_dict() for ins in self.instructions]
        }
        if self.intent is not None:
            result["intent"] = self.intent
        if self.case_id is not None:
            result["case_id"] = self.case_id
        if self.target_id is not None:
            result["target_id"] = self.target_id
        if self.round_limit is not None:
            result["round_limit"] = self.round_limit
        if self.options:
            result["options"] = self.options
        if self.operations:
            result["operations"] = self.operations
        return result

def ast_to_ir(program: ProgramNode) -> IntermediateRepresentation:
    """Transform high-level AST into platform-independent IR representation."""
    from app.intelligence.intent_engine import IntentEngine

    ir_instructions: list[IRInstruction] = []
    primary_intent: str | None = None
    case_id: str | None = None
    target_id: str | None = None
    round_limit: int | None = None
    options: dict[str, Any] = {}
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
        elif isinstance(stmt, TargetNode):
            target_id = stmt.target_id
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="SET_TARGET",
                parameters={"target_id": stmt.target_id},
                source_line=stmt.line
            ))
        elif isinstance(stmt, RoundLimitNode):
            round_limit = stmt.limit
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="SET_ROUND_LIMIT",
                parameters={"limit": stmt.limit},
                source_line=stmt.line
            ))
        elif isinstance(stmt, OptionsNode):
            options.update(stmt.options)
            ir_instructions.append(IRInstruction(
                kind="CONFIG",
                operation="SET_OPTIONS",
                parameters=stmt.options,
                source_line=stmt.line
            ))

    if not primary_intent and resolved_operations:
        primary_intent = "suspicious_network_activity"

    return IntermediateRepresentation(
        intent=primary_intent,
        case_id=case_id,
        target_id=target_id,
        round_limit=round_limit,
        options=options,
        operations=resolved_operations,
        instructions=ir_instructions
    )
