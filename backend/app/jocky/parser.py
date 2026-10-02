from app.jocky.lexer import Token, TokenType
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
    ASTNode,
)

KNOWN_INTENTS = {
    "suspicious_network_activity",
    "possible_malware_execution",
    "system_compromise",
    # ── Evasion-Aware Intent Profiles ─────────────────────────────────────────
    "kernel_evasion_analysis",   # BYOVD driver enumeration via ctypes
    "memory_injection_hunt",     # In-memory injection detection via VirtualQueryEx
    "byovd_detection",           # Full-spectrum BYOVD + injection hunt
}

# Alias map for natural DSL syntax (e.g. COLLECT processes -> PROCESS.LIST)
COLLECT_ALIAS_MAP = {
    "PROCESSES": "PROCESS.LIST",
    "PROCESS": "PROCESS.LIST",
    "NETWORK": "NETWORK.CONNECTIONS",
    "NET": "NETWORK.CONNECTIONS",
    "CONNECTIONS": "NETWORK.CONNECTIONS",
    "SYSTEM": "SYSTEM.INFO",
    "DNS": "DNS.INFO",
    "FILES": "FILES.RECENT",
    "FILESYSTEM": "FILES.RECENT",
    "USERS": "USERS.LIST",
    "ACCOUNTS": "USERS.LIST",
    "EVENTS": "EVENTLOG.RECENT",
    "EVENTLOG": "EVENTLOG.RECENT",
    "DRIVERS": "DRIVERS.LIST",
    "MEMORY": "MEMORY.ANALYSIS",
    "TIMELINE": "TIMELINE.CREATE",
    "REPORT": "REPORT.GENERATE",
}

class ParserError(Exception):
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Line {line}, Column {column}: {message}")

class UnknownIntentError(ParserError):
    def __init__(self, intent: str, line: int, column: int, supported: list[str] | None = None):
        self.intent = intent
        self.supported = supported or sorted(list(KNOWN_INTENTS))
        supported_str = ", ".join(self.supported)
        msg = f"Unknown investigation intent '{intent}'.\nSupported intents: {supported_str}"
        super().__init__(msg, line, column)

class EmptyDSLError(ParserError):
    def __init__(self, message: str = "JOCKY script contains no executable statements. Provide an investigative intent (e.g. INVESTIGATE suspicious_network_activity).", line: int = 1, column: int = 1):
        super().__init__(message, line, column)

class Parser:
    def __init__(self, tokens: list[Token], validate_intent: bool = True):
        self.tokens = [t for t in tokens if t.type != TokenType.COMMENT]
        self.cursor = 0
        self.validate_intent = validate_intent

    def _peek(self, offset: int = 0) -> Token:
        pos = self.cursor + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]  # Return EOF

    def _advance(self) -> Token:
        tok = self._peek()
        if tok.type != TokenType.EOF:
            self.cursor += 1
        return tok

    def _match(self, expected_type: TokenType) -> Token:
        tok = self._peek()
        if tok.type == expected_type:
            return self._advance()
        raise ParserError(
            f"Expected token {expected_type.name}, found {tok.type.name} ('{tok.value}')",
            tok.line, tok.column
        )

    def parse(self) -> ProgramNode:
        statements: list[ASTNode] = []

        while self._peek().type != TokenType.EOF:
            # Skip empty newlines between statements
            if self._peek().type == TokenType.NEWLINE:
                self._advance()
                continue

            tok = self._peek()

            # 1. INVESTIGATE <intent>
            if tok.type == TokenType.KEYWORD_INVESTIGATE:
                inv_tok = self._advance()
                if self._peek().type != TokenType.IDENTIFIER:
                    raise ParserError(
                        "Expected an investigation intent after INVESTIGATE.\n\nExample:\nINVESTIGATE suspicious_network_activity",
                        self._peek().line, self._peek().column
                    )
                intent_tok = self._advance()
                if self.validate_intent and intent_tok.value not in KNOWN_INTENTS:
                    raise UnknownIntentError(
                        intent=intent_tok.value,
                        line=intent_tok.line,
                        column=intent_tok.column
                    )
                statements.append(InvestigateNode(
                    intent=intent_tok.value,
                    line=inv_tok.line,
                    column=inv_tok.column
                ))

            # 2. CASE "<case_id>" or CASE <identifier>
            elif tok.type == TokenType.KEYWORD_CASE:
                case_tok = self._advance()
                if self._peek().type not in (TokenType.STRING, TokenType.IDENTIFIER):
                    raise ParserError(
                        "Expected case identifier after CASE, e.g. CASE \"incident-001\"",
                        self._peek().line, self._peek().column
                    )
                val_tok = self._advance()
                statements.append(CaseNode(
                    case_id=val_tok.value,
                    line=case_tok.line,
                    column=case_tok.column
                ))

            # 3. COLLECT <identifier>
            elif tok.type == TokenType.KEYWORD_COLLECT:
                coll_tok = self._advance()
                if self._peek().type not in (TokenType.IDENTIFIER, TokenType.OPERATION):
                    raise ParserError(
                        "Expected collector target after COLLECT, e.g. COLLECT processes",
                        self._peek().line, self._peek().column
                    )
                target_tok = self._advance()
                upper_val = target_tok.value.upper()
                op_name = COLLECT_ALIAS_MAP.get(upper_val, upper_val)
                statements.append(OperationNode(
                    operation=op_name,
                    line=coll_tok.line,
                    column=coll_tok.column
                ))

            # 4. CHAIN [evidence|records]
            elif tok.type == TokenType.KEYWORD_CHAIN:
                chain_tok = self._advance()
                target = "evidence"
                if self._peek().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    target = self._advance().value
                statements.append(ChainNode(
                    target=target,
                    line=chain_tok.line,
                    column=chain_tok.column
                ))

            # 5. SIGN [ED25519|key]
            elif tok.type == TokenType.KEYWORD_SIGN:
                sign_tok = self._advance()
                algo = "ED25519"
                if self._peek().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    algo = self._advance().value.upper()
                statements.append(SignNode(
                    algorithm=algo,
                    line=sign_tok.line,
                    column=sign_tok.column
                ))

            # 6. VERIFY [evidence|chain|signature]
            elif tok.type == TokenType.KEYWORD_VERIFY:
                ver_tok = self._advance()
                target = "chain"
                if self._peek().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    target = self._advance().value
                statements.append(VerifyNode(
                    target=target,
                    line=ver_tok.line,
                    column=ver_tok.column
                ))

            # 7. EXPORT [evidence|package]
            elif tok.type == TokenType.KEYWORD_EXPORT:
                exp_tok = self._advance()
                target = "evidence"
                if self._peek().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    target = self._advance().value
                statements.append(ExportNode(
                    target=target,
                    line=exp_tok.line,
                    column=exp_tok.column
                ))

            # 8. HASH [SHA256]
            elif tok.type == TokenType.KEYWORD_HASH:
                hash_tok = self._advance()
                target = "SHA256"
                if self._peek().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    target = self._advance().value
                # No-op or configuration instruction in the pipeline
                statements.append(OperationNode(
                    operation="CHAIN.BUILD",
                    params={"algorithm": target},
                    line=hash_tok.line,
                    column=hash_tok.column
                ))

            # 9. FILE.HASH "<path>"
            elif tok.type == TokenType.OPERATION and tok.value == "FILE.HASH":
                op_tok = self._advance()
                if self._peek().type != TokenType.STRING:
                    raise ParserError(
                        "FILE.HASH requires a quoted file path, e.g. FILE.HASH \"sample.exe\"",
                        self._peek().line, self._peek().column
                    )
                path_tok = self._advance()
                statements.append(FileHashNode(
                    path=path_tok.value,
                    line=op_tok.line,
                    column=op_tok.column
                ))

            # 10. Standard Forensic Operation (e.g. PROCESS.LIST, SYSTEM.INFO, CHAIN.BUILD)
            elif tok.type == TokenType.OPERATION:
                op_tok = self._advance()
                statements.append(OperationNode(
                    operation=op_tok.value,
                    line=op_tok.line,
                    column=op_tok.column
                ))

            else:
                raise ParserError(
                    f"Unexpected statement beginning with '{tok.value}'",
                    tok.line, tok.column
                )

        if not statements:
            raise EmptyDSLError()

        return ProgramNode(statements=statements)
