from dataclasses import dataclass, field, asdict
from typing import Any
from app.intelligence.correlation_engine import CorrelationMatchResult
from app.core.config import settings

@dataclass
class EscalationDecision:
    should_escalate: bool
    trigger_rule: str | None = None
    new_operations: list[str] = field(default_factory=list)
    round_number: int = 2
    reason: str = ""
    status_label: str = "investigation escalated"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class AdaptiveEscalationEngine:
    """
    Core research engine: Evaluates correlation matches against execution history
    to dynamically adapt and expand the investigative workflow while strictly
    enforcing loop prevention and idempotency.
    """

    def __init__(self, max_rounds: int | None = None):
        self.max_rounds = max_rounds or settings.MAX_ROUNDS

    def evaluate_escalation(
        self,
        current_round: int,
        matches: list[CorrelationMatchResult],
        executed_operations: set[str],
        triggered_rules: set[str]
    ) -> EscalationDecision:
        """
        Determine whether the investigation should escalate to a new round.
        
        Guards:
        1. Round ceiling: (current_round >= max_rounds) -> terminates
        2. Execution deduplication: any operation in executed_operations is skipped
        3. Rule deduplication: any rule in triggered_rules is skipped
        """
        # Guard 1: Loop prevention via max rounds ceiling
        if current_round >= self.max_rounds:
            return EscalationDecision(
                should_escalate=False,
                reason=f"Maximum investigative round ceiling reached ({self.max_rounds}). Investigation completed.",
                status_label="investigation complete"
            )

        if not matches:
            return EscalationDecision(
                should_escalate=False,
                reason="No new correlation indicators detected. Investigation converged.",
                status_label="investigation complete"
            )

        # Evaluate candidate matches
        for match in matches:
            # Guard 2: Skip rules that have already triggered an escalation
            if match.rule_name in triggered_rules:
                continue

            # Candidate recommended operations
            candidates = match.recommended_operations
            # Guard 3: Filter out already executed operations
            new_ops = [op for op in candidates if op not in executed_operations]

            if new_ops:
                next_round = current_round + 1
                return EscalationDecision(
                    should_escalate=True,
                    trigger_rule=match.rule_name,
                    new_operations=new_ops,
                    round_number=next_round,
                    reason=f"Escalation rule {match.rule_name} matched: additional evidence recommended.",
                    status_label="investigation escalated"
                )

        return EscalationDecision(
            should_escalate=False,
            reason="All recommended operations for matched rules have already been executed.",
            status_label="investigation complete"
        )
