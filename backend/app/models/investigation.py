from datetime import datetime, timezone
from typing import Any
# pyrefly: ignore [missing-import]
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Any = Column(String(64), primary_key=True, index=True)
    intent: Any = Column(String(128), nullable=False)
    script: Any = Column(Text, nullable=True)
    machine_id: Any = Column(String(64), ForeignKey("machines.id"), nullable=False)
    status: Any = Column(String(32), default="CREATED")  # CREATED, IN_PROGRESS, COMPLETED, PARTIALLY_COMPLETED, FAILED
    current_round: Any = Column(Integer, default=1)
    total_rounds: Any = Column(Integer, default=1)
    start_time: Any = Column(DateTime, default=_utc_now)
    end_time: Any = Column(DateTime, nullable=True)
    summary: Any = Column(Text, nullable=True)
    created_at: Any = Column(DateTime, default=_utc_now)

    # Relationships
    machine = relationship("Machine", back_populates="investigations")
    rounds = relationship("InvestigationRound", back_populates="investigation", cascade="all, delete-orphan")
    workflow_steps = relationship("WorkflowStep", back_populates="investigation", cascade="all, delete-orphan")
    artifacts = relationship("EvidenceArtifact", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    correlation_matches = relationship("CorrelationMatch", back_populates="investigation", cascade="all, delete-orphan")
    escalation_actions = relationship("EscalationAction", back_populates="investigation", cascade="all, delete-orphan")
    execution_logs = relationship("ExecutionLog", back_populates="investigation", cascade="all, delete-orphan")


class InvestigationRound(Base):
    __tablename__ = "investigation_rounds"

    id: Any = Column(String(64), primary_key=True, index=True)
    investigation_id: Any = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    round_number: Any = Column(Integer, nullable=False)
    trigger_reason: Any = Column(Text, nullable=False)  # e.g., "Initial investigation requirement" or "Escalation rule POWERSHELL_NETWORK_ACTIVITY matched"
    status: Any = Column(String(32), default="PLANNED")  # PLANNED, EXECUTING, COMPLETED, FAILED
    started_at: Any = Column(DateTime, default=_utc_now)
    completed_at: Any = Column(DateTime, nullable=True)

    # Relationships
    investigation = relationship("Investigation", back_populates="rounds")
    workflow_steps = relationship("WorkflowStep", back_populates="round_obj")
    correlation_matches = relationship("CorrelationMatch", back_populates="round_obj")
    escalation_actions = relationship("EscalationAction", back_populates="round_obj")
