from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(String(64), primary_key=True, index=True)  # e.g., EV-001
    name = Column(String(128), nullable=False)            # e.g., processes.json
    artifact_type = Column(String(64), nullable=False)     # e.g., JSON_PROCESS_LIST
    collector = Column(String(64), nullable=False)         # e.g., PROCESS.LIST
    operation = Column(String(64), nullable=False)         # e.g., PROCESS.LIST
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    step_id = Column(String(64), ForeignKey("workflow_steps.id"), nullable=True)
    machine_id = Column(String(64), ForeignKey("machines.id"), nullable=False)
    round_number = Column(Integer, default=1)
    reason = Column(Text, nullable=False)                  # e.g., "Initial investigation requirement" or "Escalation rule POWERSHELL_NETWORK_ACTIVITY matched"
    file_path = Column(String(256), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    sha256 = Column(String(64), nullable=False)
    integrity_status = Column(String(32), default="VALID") # VALID, INTEGRITY_MISMATCH
    is_synthetic = Column(Boolean, default=False)
    collected_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", back_populates="artifacts")
    step = relationship("WorkflowStep", back_populates="artifacts")
    machine = relationship("Machine", back_populates="artifacts")
    provenance = relationship("ProvenanceRecord", back_populates="artifact", uselist=False, cascade="all, delete-orphan")


class ProvenanceRecord(Base):
    __tablename__ = "provenance_records"

    id = Column(String(64), primary_key=True, index=True)
    artifact_id = Column(String(64), ForeignKey("evidence_artifacts.id"), nullable=False, unique=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    intent = Column(String(128), nullable=False)
    collector = Column(String(64), nullable=False)
    operation = Column(String(64), nullable=False)
    machine_id = Column(String(64), nullable=False)
    round_number = Column(Integer, default=1)
    reason = Column(Text, nullable=False)
    sha256 = Column(String(64), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)
    recorded_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(Text, nullable=True)

    # ── Evidence Integrity 2.0: Hash Chain & Signatures ──────────────────────
    sequence_number = Column(Integer, default=1, index=True)
    previous_record_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=True, index=True)
    key_id = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)

    # Relationships
    artifact = relationship("EvidenceArtifact", back_populates="provenance")


class EvidenceChainManifest(Base):
    __tablename__ = "evidence_chain_manifests"

    id = Column(String(64), primary_key=True, index=True)  # e.g., CHAIN-INV-20260928-001
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False, unique=True, index=True)
    case_id = Column(String(64), nullable=False, default="CASE-DEFAULT")
    genesis_hash = Column(String(64), nullable=False)
    chain_tip = Column(String(64), nullable=False)
    record_count = Column(Integer, default=0)
    first_timestamp = Column(DateTime, nullable=True)
    last_timestamp = Column(DateTime, nullable=True)
    signature_algorithm = Column(String(32), default="Ed25519")
    public_key_pem = Column(Text, nullable=True)
    public_key_hex = Column(String(128), nullable=True)
    key_id = Column(String(64), nullable=True)
    signature_hex = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

