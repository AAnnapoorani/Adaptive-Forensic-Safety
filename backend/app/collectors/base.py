from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class CollectorResult(BaseModel):
    collector_name: str
    operation: str
    status: str = "SUCCESS"  # SUCCESS, PARTIALLY_COMPLETED, FAILED, NOT_AVAILABLE
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    data: Any = None
    item_count: int = 0
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class BaseCollector(ABC):
    name: str
    operation: str
    description: str

    @abstractmethod
    def collect(self, params: dict[str, Any] | None = None) -> CollectorResult:
        """Execute safe, read-only forensic collection."""
        pass
