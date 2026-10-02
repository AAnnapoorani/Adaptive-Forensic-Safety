import difflib
from enum import Enum, auto
from dataclasses import dataclass

class TokenType(Enum):
    KEYWORD_INVESTIGATE = auto()
    KEYWORD_CASE = auto()
    KEYWORD_COLLECT = auto()
    KEYWORD_CHAIN = auto()
    KEYWORD_SIGN = auto()
    KEYWORD_VERIFY = auto()
    KEYWORD_EXPORT = auto()
    KEYWORD_HASH = auto()
    OPERATION = auto()
    IDENTIFIER = auto()
    STRING = auto()
    COMMENT = auto()
    NEWLINE = auto()
    EOF = auto()

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int

KNOWN_OPERATIONS = {
    "SYSTEM.INFO",
    "PROCESS.LIST",
    "NETWORK.CONNECTIONS",
    "DNS.INFO",
    "USERS.LIST",
    "FILES.RECENT",
    "FILE.HASH",
    "EVENTLOG.RECENT",
    "PROCESS.PARENT_CHILD",
    "COMMANDLINE.INFO",
    "TIMELINE.CREATE",
    "REPORT.GENERATE",
    # ── Evasion-Aware Operations ──────────────────────────────────────
    "DRIVERS.LIST",     # BYOVD kernel driver enumeration (ctypes Win32)
    "MEMORY.ANALYSIS",  # In-memory injection detection (VirtualQueryEx)
    # ── Integrity 2.0 Operations ──────────────────────────────────────
    "CHAIN.BUILD",
    "CHAIN.SIGN",
    "CHAIN.VERIFY",
    "CHAIN.EXPORT",
    # ── Phase 23: Linux eBPF Kernel Tracing ───────────────────────────
    "EBPF.TRACE",
}

KNOWN_KEYWORDS = {
    "INVESTIGATE",
    "CASE",
    "COLLECT",
    "CHAIN",
    "SIGN",
    "VERIFY",
    "EXPORT",
    "HASH"
}

KEYWORD_MAP = {
    "INVESTIGATE": TokenType.KEYWORD_INVESTIGATE,
    "CASE": TokenType.KEYWORD_CASE,
    "COLLECT": TokenType.KEYWORD_COLLECT,
    "CHAIN": TokenType.KEYWORD_CHAIN,
    "SIGN": TokenType.KEYWORD_SIGN,
    "VERIFY": TokenType.KEYWORD_VERIFY,
    "EXPORT": TokenType.KEYWORD_EXPORT,
    "HASH": TokenType.KEYWORD_HASH,
}

class LexerError(Exception):
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Line {line}, Column {column}: {message}")

class Lexer:
    def __init__(self, source_code: str):
        self.source = source_code
        self.length = len(source_code)
        self.cursor = 0
        self.line = 1
        self.column = 1

    def _peek(self, offset: int = 0) -> str:
        pos = self.cursor + offset
        if pos < self.length:
            return self.source[pos]
        return ""

    def _advance(self) -> str:
        if self.cursor < self.length:
            ch = self.source[self.cursor]
            self.cursor += 1
            if ch == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            return ch
        return ""

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []

        while self.cursor < self.length:
            ch = self._peek()

            # Whitespace (excluding newline)
            if ch in (" ", "\t", "\r"):
                self._advance()
                continue

            # Newline
            if ch == "\n":
                line, col = self.line, self.column
                self._advance()
                tokens.append(Token(TokenType.NEWLINE, "\n", line, col))
                continue

            # Comment starting with '#'
            if ch == "#":
                line, col = self.line, self.column
                comment_chars = []
                while self._peek() and self._peek() != "\n":
                    comment_chars.append(self._advance())
                tokens.append(Token(TokenType.COMMENT, "".join(comment_chars), line, col))
                continue

            # Quoted String "..."
            if ch in ('"', "'"):
                quote_char = ch
                line, col = self.line, self.column
                self._advance()  # Skip opening quote
                str_chars = []
                closed = False
                while self._peek():
                    cur = self._peek()
                    if cur == quote_char:
                        self._advance()  # Skip closing quote
                        closed = True
                        break
                    elif cur == "\n":
                        raise LexerError("Unterminated string literal before newline", line, col)
                    else:
                        str_chars.append(self._advance())

                if not closed:
                    raise LexerError("Unterminated string literal at EOF", line, col)

                tokens.append(Token(TokenType.STRING, "".join(str_chars), line, col))
                continue

            # Words: Keywords, Operations (e.g. PROCESS.LIST), or Identifiers
            if ch.isalpha() or ch == "_":
                line, col = self.line, self.column
                word_chars = []
                while self._peek() and (self._peek().isalnum() or self._peek() in ("_", ".")):
                    word_chars.append(self._advance())
                
                word = "".join(word_chars)
                upper_word = word.upper()

                if upper_word in KEYWORD_MAP:
                    tokens.append(Token(KEYWORD_MAP[upper_word], upper_word, line, col))
                elif upper_word in KNOWN_OPERATIONS:
                    tokens.append(Token(TokenType.OPERATION, upper_word, line, col))
                else:
                    # Check for probable typo in known operations or keywords
                    all_candidates = list(KNOWN_OPERATIONS) + list(KNOWN_KEYWORDS)
                    matches = difflib.get_close_matches(upper_word, all_candidates, n=1, cutoff=0.7)
                    if matches and "." in word:
                        raise LexerError(
                            f"Unknown operation: '{word}'\nDid you mean: {matches[0]}",
                            line, col
                        )
                    # If it has a dot, it was likely an intended operation
                    if "." in word:
                        all_ops = list(KNOWN_OPERATIONS)
                        closest = difflib.get_close_matches(upper_word, all_ops, n=1, cutoff=0.4)
                        suggestion = f"\nDid you mean: {closest[0]}" if closest else ""
                        raise LexerError(f"Unknown operation: '{word}'{suggestion}", line, col)

                    # Otherwise it is an identifier (such as intent name, target name, etc.)
                    tokens.append(Token(TokenType.IDENTIFIER, word, line, col))
                continue

            # Unexpected character
            raise LexerError(f"Unexpected character: '{ch}'", self.line, self.column)

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens
