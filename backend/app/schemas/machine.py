from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class MachineResponse(BaseModel):
    id: str
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    last_seen: datetime

    class Config:
        from_attributes = True
