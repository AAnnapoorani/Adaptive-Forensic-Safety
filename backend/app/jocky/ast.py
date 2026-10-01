from dataclasses import dataclass, field
from typing import Any

@dataclass
class ASTNode:
    line: int = 1
    column: int = 1

@dataclass
class InvestigateNode(ASTNode):
    intent: str = ""

@dataclass
class CaseNode(ASTNode):
    case_id: str = ""

@dataclass
class OperationNode(ASTNode):
    operation: str = ""
    params: dict[str, Any] = field(default_factory=dict)

@dataclass
class FileHashNode(ASTNode):
    path: str = ""

# ── Integrity 2.0 AST Nodes ──────────────────────────────────────────────────

@dataclass
class ChainNode(ASTNode):
    target: str = "evidence"  # e.g., CHAIN evidence

@dataclass
class SignNode(ASTNode):
    algorithm: str = "ED25519"  # e.g., SIGN ED25519

@dataclass
class VerifyNode(ASTNode):
    target: str = "chain"  # e.g., VERIFY evidence, VERIFY chain, VERIFY signature

@dataclass
class ExportNode(ASTNode):
    target: str = "evidence"  # e.g., EXPORT evidence

@dataclass
class TargetNode(ASTNode):
    target_id: str = ""

@dataclass
class RoundLimitNode(ASTNode):
    limit: int = 3

@dataclass
class OptionsNode(ASTNode):
    options: dict[str, Any] = field(default_factory=dict)

@dataclass
class ProgramNode(ASTNode):
    statements: list[ASTNode] = field(default_factory=list)
