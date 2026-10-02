from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class WorkflowStep(Base):
    __tablename__ = "workflow_steps"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    round_id = Column(String(64), ForeignKey("investigation_rounds.id"), nullable=True)
    operation = Column(String(64), nullable=False)  # e.g., SYSTEM.INFO, PROCESS.LIST
    priority = Column(Integer, default=1)
    status = Column(String(32), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED, SKIPPED
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="workflow_steps")
    round_obj = relationship("InvestigationRound", back_populates="workflow_steps")
    artifacts = relationship("EvidenceArtifact", back_populates="step")
