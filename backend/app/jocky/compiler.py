from typing import Any
from app.jocky.lexer import Lexer, LexerError
from app.jocky.parser import Parser, ParserError, UnknownIntentError, EmptyDSLError
from app.jocky.ir import ast_to_ir, IntermediateRepresentation
from app.jocky.ast import ProgramNode

class CompilationError(Exception):
    def __init__(self, message: str, line: int = 1, column: int = 1, error_type: str = "SYNTAX_ERROR"):
        self.message = message
        self.line = line
        self.column = column
        self.error_type = error_type
        super().__init__(f"Line {line}, Column {column}: {message}")

class JockyCompiler:
    @staticmethod
    def compile(source_code: str, validate_intent: bool = True) -> tuple[ProgramNode, IntermediateRepresentation]:
        """Compile JOCKY script from source code through Lexer, Parser, AST, and IR."""
        if not source_code or not source_code.strip():
            raise EmptyDSLError("JOCKY script is empty. Provide an investigative intent (e.g. INVESTIGATE suspicious_network_activity).", 1, 1)

        try:
            lexer = Lexer(source_code)
            tokens = lexer.tokenize()
        except LexerError as le:
            raise CompilationError(le.message, le.line, le.column, error_type="LEXER_ERROR")

        try:
            parser = Parser(tokens, validate_intent=validate_intent)
            ast_root = parser.parse()
        except UnknownIntentError as uie:
            raise uie
        except EmptyDSLError as ede:
            raise ede
        except ParserError as pe:
            raise CompilationError(pe.message, pe.line, pe.column, error_type="PARSER_ERROR")

        ir = ast_to_ir(ast_root)
        return ast_root, ir

    @staticmethod
    def inspect(source_code: str, investigation_id: str = "INV-PREVIEW") -> dict[str, Any]:
        """Full compiler pipeline inspection for UI and debugging."""
        from app.intelligence.evidence_graph import build_evidence_graph_for_intent
        from app.intelligence.workflow_planner import WorkflowCompiler

        if not source_code or not source_code.strip():
            raise EmptyDSLError("JOCKY script is empty. Provide an investigative intent (e.g. INVESTIGATE suspicious_network_activity).", 1, 1)

        lexer = Lexer(source_code)
        tokens = lexer.tokenize()

        parser = Parser(tokens, validate_intent=True)
        ast_root = parser.parse()
        ir = ast_to_ir(ast_root)

        intent = ir.intent or "suspicious_network_activity"
        ops = list(ir.operations)
        graph = build_evidence_graph_for_intent(intent, ops)
        workflow = WorkflowCompiler.compile(graph, investigation_id=investigation_id, round_number=1)

        return {
            "source_code": source_code,
            "tokens": [
                {"type": t.type.name, "value": t.value, "line": t.line, "column": t.column}
                for t in tokens if t.type.name != "EOF"
            ],
            "parsed_intent": intent,
            "ir": ir.to_dict(),
            "planned_operations": ops,
            "evidence_graph": graph.to_dict(),
            "workflow": workflow.to_dict()
        }
