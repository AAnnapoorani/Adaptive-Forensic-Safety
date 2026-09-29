from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime

class CreateInvestigationRequest(BaseModel):
    intent: Optional[str] = "suspicious_network_activity"
    script: Optional[str] = None
    machine_id: Optional[str] = None

class PreviewScriptRequest(BaseModel):
    intent: Optional[str] = "suspicious_network_activity"
    script: Optional[str] = None


class InvestigationSummary(BaseModel):
    id: str
    intent: str
    status: str
    current_round: int
    total_rounds: int
    machine_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    created_at: datetime
    artifact_count: int = 0
    correlation_count: int = 0
    timeline_count: int = 0
    escalation_triggered: bool = False

    class Config:
        from_attributes = True

class InvestigationDetailResponse(BaseModel):
    id: str
    intent: str
    script: Optional[str] = None
    status: str
    current_round: int
    total_rounds: int
    machine_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    created_at: datetime
    summary: Optional[str] = None
    metrics: dict[str, Any] = Field(default_factory=dict)
