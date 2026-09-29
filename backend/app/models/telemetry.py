from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Column, String, DateTime, Float, Integer, BigInteger, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class MachineTelemetry(Base):
    """Time-series system telemetry snapshots sent by local JOCKY agents."""
    __tablename__ = "machine_telemetry"

    id: Any = Column(String(64), primary_key=True, index=True)
    machine_id: Any = Column(String(64), ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Any = Column(DateTime, default=_utc_now, index=True, nullable=False)

    # CPU metrics
    cpu_percent: Any = Column(Float, default=0.0)
    cpu_freq_mhz: Any = Column(Float, nullable=True)
    cpu_cores: Any = Column(Integer, nullable=True)

    # Memory metrics
    memory_total_bytes: Any = Column(BigInteger, default=0)
    memory_used_bytes: Any = Column(BigInteger, default=0)
    memory_available_bytes: Any = Column(BigInteger, default=0)
    memory_percent: Any = Column(Float, default=0.0)

    # Disk metrics
    disk_total_bytes: Any = Column(BigInteger, default=0)
    disk_used_bytes: Any = Column(BigInteger, default=0)
    disk_free_bytes: Any = Column(BigInteger, default=0)
    disk_percent: Any = Column(Float, default=0.0)

    # Network metrics
    network_bytes_sent: Any = Column(BigInteger, default=0)
    network_bytes_recv: Any = Column(BigInteger, default=0)
    network_upload_speed: Any = Column(Float, default=0.0)   # bytes/sec
    network_download_speed: Any = Column(Float, default=0.0) # bytes/sec
    active_connections: Any = Column(Integer, default=0)

    # Relationship
    machine = relationship("Machine", back_populates="telemetry")


class MachineProcessSnapshot(Base):
    """Running process snapshot recorded by the local JOCKY agent."""
    __tablename__ = "machine_processes"

    id: Any = Column(String(64), primary_key=True, index=True)
    machine_id: Any = Column(String(64), ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Any = Column(DateTime, default=_utc_now, index=True, nullable=False)

    pid: Any = Column(Integer, nullable=False)
    name: Any = Column(String(128), nullable=False)
    exe_path: Any = Column(Text, nullable=True)
    username: Any = Column(String(128), nullable=True)
    cpu_percent: Any = Column(Float, default=0.0)
    memory_percent: Any = Column(Float, default=0.0)
    memory_rss_bytes: Any = Column(BigInteger, default=0)
    status: Any = Column(String(32), default="running")
    create_time: Any = Column(String(64), nullable=True)
    threat_level: Any = Column(String(32), default="CLEAN") # CLEAN, SUSPICIOUS, HIGH, CRITICAL
    matched_rules_json: Any = Column(Text, nullable=True)   # JSON string list of matched rule IDs/names

    # Relationship
    machine = relationship("Machine", back_populates="processes")


class ForensicEvent(Base):
    """Structured security and forensic event detected on an agent machine."""
    __tablename__ = "forensic_events"

    id: Any = Column(String(64), primary_key=True, index=True)
    machine_id: Any = Column(String(64), ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Any = Column(DateTime, default=_utc_now, index=True, nullable=False)

    event_type: Any = Column(String(64), nullable=False)  # SUSPICIOUS_PROCESS, NETWORK_CONNECTION, etc.
    severity: Any = Column(String(32), default="INFO", nullable=False) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source: Any = Column(String(64), nullable=False)     # Windows Event Log, Linux Proc Monitor, etc.
    description: Any = Column(Text, nullable=False)

    process_name: Any = Column(String(128), nullable=True)
    pid: Any = Column(Integer, nullable=True)
    user: Any = Column(String(128), nullable=True)
    remote_ip: Any = Column(String(64), nullable=True)
    metadata_json: Any = Column(Text, nullable=True)

    # Relationship
    machine = relationship("Machine", back_populates="events")


class AgentTriageCommand(Base):
    """Remote read-only forensic triage commands dispatched to a machine agent."""
    __tablename__ = "agent_triage_commands"

    id: Any = Column(String(64), primary_key=True, index=True)
    machine_id: Any = Column(String(64), ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    command: Any = Column(String(256), nullable=False)
    status: Any = Column(String(32), default="PENDING", index=True) # PENDING, RUNNING, COMPLETED, FAILED
    dispatched_at: Any = Column(DateTime, default=_utc_now, nullable=False)
    completed_at: Any = Column(DateTime, nullable=True)
    exit_code: Any = Column(Integer, nullable=True)
    output: Any = Column(Text, nullable=True)
    error: Any = Column(Text, nullable=True)
    signed_hash: Any = Column(String(64), nullable=True) # SHA-256 tamper-evident seal

    # Relationship
    machine = relationship("Machine", back_populates="commands")
