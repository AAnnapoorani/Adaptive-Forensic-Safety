from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.investigation import Investigation, InvestigationRound
from app.models.workflow import WorkflowStep
from app.models.evidence import EvidenceArtifact
from app.models.execution import CorrelationMatch, EscalationAction
from app.models.timeline import TimelineEvent
from app.schemas.investigation import CreateInvestigationRequest, PreviewScriptRequest
from app.services.investigation_service import InvestigationService
from app.jocky.lexer import LexerError
from app.jocky.parser import ParserError, UnknownIntentError, EmptyDSLError
from app.jocky.compiler import CompilationError
from app.utils.datetime_utils import to_iso_utc

router = APIRouter(prefix="/investigations", tags=["Investigations"])

@router.post("/preview")
def preview_script(req: PreviewScriptRequest):
    """Preview compilation, evidence DAG, and workflow steps from a JOCKY script or intent without persisting to the database."""
    try:
        return InvestigationService.preview_script(script=req.script, intent=req.intent or "suspicious_network_activity")
    except (EmptyDSLError, UnknownIntentError, LexerError, ParserError, CompilationError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("")
def create_investigation(req: CreateInvestigationRequest, db: Session = Depends(get_db)):
    """Create a new forensic investigation from high-level intent or custom JOCKY script."""
    try:
        inv = InvestigationService.create_investigation(
            db=db,
            intent=req.intent or "suspicious_network_activity",
            script=req.script,
            machine_id=req.machine_id
        )
        exec_summary = None
        artifacts_collected = 0
        if req.auto_execute:
            try:
                exec_res = InvestigationService.execute_investigation(db=db, investigation_id=str(inv.id), demo_mode=False)
                exec_summary = exec_res.get("summary")
                artifacts_collected = exec_res.get("artifacts_collected", 0)

                # Broadcast autonomous security alert via SSE
                from app.core.sse import sse_manager
                sse_manager.broadcast_sync("security_alert", {
                    "alert_type": "AUTONOMOUS_INCIDENT_TRIAGE",
                    "investigation_id": str(inv.id),
                    "machine_id": str(inv.machine_id),
                    "intent": str(inv.intent),
                    "status": "COMPLETED",
                    "evidence_count": artifacts_collected,
                    "integrity_verified": exec_res.get("integrity_verified", True)
                })
            except Exception as ex:
                print(f"[Warning] Auto-execution failed: {ex}")

        return {
            "id": inv.id,
            "intent": inv.intent,
            "status": "COMPLETED" if req.auto_execute and exec_summary else inv.status,
            "machine_id": inv.machine_id,
            "created_at": to_iso_utc(inv.created_at),
            "auto_executed": req.auto_execute,
            "artifacts_collected": artifacts_collected,
            "summary": exec_summary
        }
    except (EmptyDSLError, UnknownIntentError, LexerError, ParserError, CompilationError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
def list_investigations(db: Session = Depends(get_db)):
    """List all registered forensic investigations."""
    invs = db.query(Investigation).order_by(Investigation.created_at.desc()).all()
    results = []
    for inv in invs:
        art_count = db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == inv.id).count()
        corr_count = db.query(CorrelationMatch).filter(CorrelationMatch.investigation_id == inv.id).count()
        tl_count = db.query(TimelineEvent).filter(TimelineEvent.investigation_id == inv.id).count()
        has_escalated = db.query(EscalationAction).filter(EscalationAction.investigation_id == inv.id).count() > 0

        results.append({
            "id": inv.id,
            "intent": inv.intent,
            "status": inv.status,
            "machine_id": inv.machine_id,
            "current_round": inv.current_round,
            "total_rounds": inv.total_rounds,
            "start_time": to_iso_utc(inv.start_time),
            "end_time": to_iso_utc(inv.end_time),
            "created_at": to_iso_utc(inv.created_at),
            "artifact_count": art_count,
            "correlation_count": corr_count,
            "timeline_count": tl_count,
            "escalation_triggered": has_escalated
        })
    return results

@router.get("/{investigation_id}")
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Get complete investigation details and aggregated metrics."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    art_count = db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == inv.id).count()
    corr_count = db.query(CorrelationMatch).filter(CorrelationMatch.investigation_id == inv.id).count()
    tl_count = db.query(TimelineEvent).filter(TimelineEvent.investigation_id == inv.id).count()
    rounds = db.query(InvestigationRound).filter(InvestigationRound.investigation_id == inv.id).all()
    escalations = db.query(EscalationAction).filter(EscalationAction.investigation_id == inv.id).all()

    return {
        "id": inv.id,
        "intent": inv.intent,
        "script": inv.script,
        "status": inv.status,
        "machine_id": inv.machine_id,
        "current_round": inv.current_round,
        "total_rounds": len(rounds) or inv.total_rounds,
        "start_time": to_iso_utc(inv.start_time),
        "end_time": to_iso_utc(inv.end_time),
        "created_at": to_iso_utc(inv.created_at),
        "summary": inv.summary,
        "metrics": {
            "total_artifacts": art_count,
            "correlation_matches": corr_count,
            "timeline_events": tl_count,
            "rounds_count": len(rounds),
            "escalation_triggered": len(escalations) > 0
        }
    }

@router.post("/{investigation_id}/preview")
def preview_investigation_plan(investigation_id: str, db: Session = Depends(get_db)):
    """Preview the compiled Evidence Requirement Graph and prioritized workflow prior to execution."""
    try:
        return InvestigationService.preview_investigation(db, investigation_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{investigation_id}/execute")
def execute_investigation(investigation_id: str, demo: bool = False, db: Session = Depends(get_db)):
    """Execute adaptive forensic workflow, multi-round collection, correlation, and synthesis."""
    try:
        return InvestigationService.execute_investigation(db, investigation_id, demo_mode=demo)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/{investigation_id}/plan")
def get_investigation_plan(investigation_id: str, db: Session = Depends(get_db)):
    """Get active plan and executed steps for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    steps = db.query(WorkflowStep).filter(
        WorkflowStep.investigation_id == investigation_id
    ).order_by(WorkflowStep.round_id.asc(), WorkflowStep.priority.asc()).all()

    # Also generate current graph
    preview = InvestigationService.preview_investigation(db, investigation_id)

    return {
        "investigation_id": inv.id,
        "intent": inv.intent,
        "evidence_graph": preview["evidence_graph"],
        "workflow_steps": [
            {
                "id": s.id,
                "operation": s.operation,
                "priority": s.priority,
                "status": s.status,
                "start_time": to_iso_utc(s.start_time),
                "end_time": to_iso_utc(s.end_time),
                "result_summary": s.result_summary,
                "error_message": s.error_message
            }
            for s in steps
        ]
    }

@router.get("/{investigation_id}/rounds")
def get_investigation_rounds(investigation_id: str, db: Session = Depends(get_db)):
    """Fetch breakdown of all execution rounds and escalation triggers."""
    rounds = db.query(InvestigationRound).filter(
        InvestigationRound.investigation_id == investigation_id
    ).order_by(InvestigationRound.round_number.asc()).all()

    result = []
    for r in rounds:
        steps = db.query(WorkflowStep).filter(WorkflowStep.round_id == r.id).all()
        arts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id,
            EvidenceArtifact.round_number == r.round_number
        ).all()
        corrs = db.query(CorrelationMatch).filter(CorrelationMatch.round_id == r.id).all()

        result.append({
            "id": r.id,
            "round_number": r.round_number,
            "trigger_reason": r.trigger_reason,
            "status": r.status,
            "started_at": to_iso_utc(r.started_at),
            "completed_at": to_iso_utc(r.completed_at),
            "steps_count": len(steps),
            "artifacts_count": len(arts),
            "correlation_matches_count": len(corrs)
        })
    return result

@router.get("/{investigation_id}/correlations")
def get_investigation_correlations(investigation_id: str, db: Session = Depends(get_db)):
    """Fetch all matched correlation rules and indicators."""
    matches = db.query(CorrelationMatch).filter(
        CorrelationMatch.investigation_id == investigation_id
    ).order_by(CorrelationMatch.round_number.asc()).all()

    return [
        {
            "id": m.id,
            "round_number": m.round_number,
            "rule_name": m.rule_name,
            "confidence": m.confidence,
            "status_label": m.status_label,
            "description": m.description,
            "matched_data": m.matched_data_json,
            "created_at": to_iso_utc(m.created_at)
        }
        for m in matches
    ]
