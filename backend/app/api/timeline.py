import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.timeline import TimelineEvent
from app.services.timeline_service import TimelineService
from app.utils.datetime_utils import to_iso_utc

router = APIRouter(tags=["Timeline"])

@router.get("/investigations/{investigation_id}/timeline")
def get_investigation_timeline(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve chronologically ordered normalized timeline events."""
    events = TimelineService.get_timeline_events(db, investigation_id)
    return [
        {
            "id": e.id,
            "timestamp": to_iso_utc(e.timestamp),
            "event_type": e.event_type,
            "description": e.description,
            "source": e.source,
            "machine_id": e.machine_id,
            "round_number": e.round_number,
            "details": json.loads(e.details_json) if e.details_json else {}
        }
        for e in events
    ]
