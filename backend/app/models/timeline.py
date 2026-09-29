from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(64), nullable=False)   # PROCESS_CREATED, NETWORK_CONNECTION, FILE_MODIFIED, EVENT_LOG, WORKFLOW_ROUND
    description = Column(Text, nullable=False)
    source = Column(String(64), nullable=False)        # e.g., PROCESS.LIST, NETWORK.CONNECTIONS, EVENTLOG.RECENT
    machine_id = Column(String(64), nullable=False)
    round_number = Column(Integer, default=1)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="timeline_events")
