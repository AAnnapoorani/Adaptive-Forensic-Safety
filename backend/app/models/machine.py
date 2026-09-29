from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class Machine(Base):
    __tablename__ = "machines"

    id: Any = Column(String(64), primary_key=True, index=True)
    machine_id: Any = Column(String(64), unique=True, index=True, nullable=True)
    hostname: Any = Column(String(128), nullable=False)
    os_type: Any = Column(String(32), default="Windows", nullable=False)  # Windows, Linux, macOS
    os_name: Any = Column(String(64), nullable=False)
    os_version: Any = Column(String(128), nullable=True)
    architecture: Any = Column(String(32), nullable=True)
    ip_address: Any = Column(String(64), nullable=True)
    mac_address: Any = Column(String(64), nullable=True)
    agent_version: Any = Column(String(32), default="1.0.0")
    status: Any = Column(String(32), default="ONLINE")
    first_seen: Any = Column(DateTime, default=_utc_now)
    last_seen: Any = Column(DateTime, default=_utc_now, onupdate=_utc_now)
    created_at: Any = Column(DateTime, default=_utc_now)
    metadata_json: Any = Column(Text, nullable=True)

    # Relationships
    telemetry = relationship("MachineTelemetry", back_populates="machine", cascade="all, delete-orphan", order_by="desc(MachineTelemetry.timestamp)")
    processes = relationship("MachineProcessSnapshot", back_populates="machine", cascade="all, delete-orphan")
    events = relationship("ForensicEvent", back_populates="machine", cascade="all, delete-orphan", order_by="desc(ForensicEvent.timestamp)")
    investigations = relationship("Investigation", back_populates="machine")
    artifacts = relationship("EvidenceArtifact", back_populates="machine")
    commands = relationship("AgentTriageCommand", back_populates="machine", cascade="all, delete-orphan", order_by="desc(AgentTriageCommand.dispatched_at)")
