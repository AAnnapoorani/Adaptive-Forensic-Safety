from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class Machine(Base):
    __tablename__ = "machines"

    id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(128), nullable=False)
    os_name = Column(String(64), nullable=False)
    os_version = Column(String(128), nullable=True)
    architecture = Column(String(32), nullable=True)
    ip_address = Column(String(64), nullable=True)
    status = Column(String(32), default="ACTIVE")
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigations = relationship("Investigation", back_populates="machine")
    artifacts = relationship("EvidenceArtifact", back_populates="machine")
