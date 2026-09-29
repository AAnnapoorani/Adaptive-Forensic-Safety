from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.services.report_service import ReportService

router = APIRouter(tags=["Reports"])

@router.get("/investigations/{investigation_id}/report")
def get_investigation_report(investigation_id: str, db: Session = Depends(get_db)):
    """Generate and retrieve the complete forensic investigation report."""
    try:
        return ReportService.generate_report(db, investigation_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/investigations/{investigation_id}/report/html", response_class=HTMLResponse)
def get_investigation_report_html(investigation_id: str, db: Session = Depends(get_db)):
    """Render full HTML printable forensic report."""
    try:
        res = ReportService.generate_report(db, investigation_id)
        return HTMLResponse(content=res["html"], status_code=200)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
