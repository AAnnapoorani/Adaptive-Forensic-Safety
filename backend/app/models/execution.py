from datetime import datetime
# pyrefly: ignore [missing-import]
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import relationship
from app.core.database import Base

class CorrelationMatch(Base):
    __tablename__ = "correlation_matches"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    round_id = Column(String(64), ForeignKey("investigation_rounds.id"), nullable=True)
    round_number = Column(Integer, default=1)
    rule_name = Column(String(128), nullable=False)    # e.g., POWERSHELL_NETWORK_ACTIVITY
    confidence = Column(String(32), default="rule_based")
    status_label = Column(String(64), default="indicator detected") # indicator detected, correlation rule matched
    description = Column(Text, nullable=False)
    matched_data_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="correlation_matches")
    round_obj = relationship("InvestigationRound", back_populates="correlation_matches")


class EscalationAction(Base):
    __tablename__ = "escalation_actions"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    round_id = Column(String(64), ForeignKey("investigation_rounds.id"), nullable=True)
    trigger_rule = Column(String(128), nullable=False)  # Rule that triggered escalation
    new_operations = Column(Text, nullable=False)       # JSON list of newly added operations
    status = Column(String(32), default="TRIGGERED")    # TRIGGERED, EXECUTED, SKIPPED
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="escalation_actions")
    round_obj = relationship("InvestigationRound", back_populates="escalation_actions")


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    component = Column(String(64), nullable=False)      # LEXER, PARSER, INTENT_ENGINE, COLLECTOR, CORRELATION, ESCALATION
    level = Column(String(16), default="INFO")          # INFO, WARNING, ERROR, AUDIT
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="execution_logs")
