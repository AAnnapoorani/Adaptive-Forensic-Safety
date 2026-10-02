from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"

    id: Any = Column(String(64), primary_key=True, index=True)
    investigation_id: Any = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    round_id: Any = Column(String(64), ForeignKey("investigation_rounds.id"), nullable=True)
    operation: Any = Column(String(64), nullable=False)  # e.g., SYSTEM.INFO, PROCESS.LIST
    priority: Any = Column(Integer, default=1)
    status: Any = Column(String(32), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED, SKIPPED
    start_time: Any = Column(DateTime, nullable=True)
    end_time: Any = Column(DateTime, nullable=True)
    error_message: Any = Column(Text, nullable=True)
    result_summary: Any = Column(Text, nullable=True)
    created_at: Any = Column(DateTime, default=_utc_now)

    # Relationships
    investigation = relationship("Investigation", back_populates="workflow_steps")
    round_obj = relationship("InvestigationRound", back_populates="workflow_steps")
    artifacts = relationship("EvidenceArtifact", back_populates="step")
