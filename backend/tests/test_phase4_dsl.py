import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.jocky.lexer import Lexer, TokenType
from app.jocky.parser import Parser
from app.jocky.compiler import JockyCompiler, CompilationError
from app.jocky.ast import InvestigateNode, FileHashNode, OperationNode

def test_phase4_jocky_dsl():
    print("Testing Phase 4: JOCKY Domain-Specific Language (Lexer, Parser, AST, IR)...")

    # 1. Test Investigation Script
    script1 = "# Investigation script\nINVESTIGATE suspicious_network_activity"
    ast1, ir1 = JockyCompiler.compile(script1)
    assert len(ast1.statements) == 1
    assert isinstance(ast1.statements[0], InvestigateNode)
    assert ast1.statements[0].intent == "suspicious_network_activity"
    assert len(ir1.instructions) == 1
    assert ir1.instructions[0].kind == "INVESTIGATION"
    assert ir1.instructions[0].parameters["intent"] == "suspicious_network_activity"
    print("[PASS] INVESTIGATE suspicious_network_activity -> Correct AST & IR")

    # 2. Test Mixed Forensic Script
    script2 = """
    # Mixed collection script
    SYSTEM.INFO
    INVESTIGATE possible_malware_execution
    FILE.HASH "malicious_binary.exe"
    TIMELINE.CREATE
    REPORT.GENERATE
    """
    ast2, ir2 = JockyCompiler.compile(script2)
    assert len(ast2.statements) == 5
    assert isinstance(ast2.statements[0], OperationNode)
    assert ast2.statements[0].operation == "SYSTEM.INFO"
    assert isinstance(ast2.statements[1], InvestigateNode)
    assert isinstance(ast2.statements[2], FileHashNode)
    assert ast2.statements[2].path == "malicious_binary.exe"
    assert isinstance(ast2.statements[3], OperationNode)
    assert isinstance(ast2.statements[4], OperationNode)
    print(f"[PASS] Mixed script compiled successfully with {len(ir2.instructions)} IR instructions.")

    # 3. Test Typo / Did You Mean Error Detection
    typo_script = "PROCES.LIST"
    try:
        JockyCompiler.compile(typo_script)
        assert False, "Expected CompilationError for typo 'PROCES.LIST'"
    except CompilationError as e:
        assert "Did you mean: PROCESS.LIST" in str(e)
        print(f"[PASS] Typo detection working: {e}")

    # 4. Test Missing Argument Handling for FILE.HASH
    bad_hash_script = "FILE.HASH"
    try:
        JockyCompiler.compile(bad_hash_script)
        assert False, "Expected CompilationError for FILE.HASH missing parameter"
    except CompilationError as e:
        assert "FILE.HASH requires a quoted file path" in str(e)
        print(f"[PASS] Missing argument error handled correctly: {e}")

if __name__ == "__main__":
    test_phase4_jocky_dsl()
    print("\n>>> ALL PHASE 4 JOCKY LANGUAGE TESTS PASSED SUCCESSFULLY! <<<\n")
