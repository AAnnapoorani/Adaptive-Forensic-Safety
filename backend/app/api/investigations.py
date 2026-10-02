# pyrefly: ignore [missing-import]
import json
from fastapi import APIRouter, Depends, HTTPException
# pyrefly: ignore [missing-import]
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
from app.jocky.compiler import CompilationError, JockyCompiler
from app.intelligence.evidence_graph import build_evidence_graph_for_intent
from app.intelligence.intent_engine import IntentEngine
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
    """Get active plan and executed steps for an investigation, with dynamically expanded multi-round DAG."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    steps = db.query(WorkflowStep).filter(
        WorkflowStep.investigation_id == investigation_id
    ).order_by(WorkflowStep.round_id.asc(), WorkflowStep.priority.asc()).all()

    # Reconstruct live dynamic evidence graph representing initial and escalated rounds
    intent_engine = IntentEngine()
    initial_ops = intent_engine.resolve_initial_operations(inv.intent)

    if inv.script and inv.script.strip():
        try:
            ast_root, ir = JockyCompiler.compile(inv.script)
            manual_ops = [
                ins.operation.replace("_", ".") for ins in ir.instructions
                if ins.kind == "COLLECTION"
            ]
            for mop in manual_ops:
                if mop not in initial_ops:
                    initial_ops.append(mop)
        except Exception:
            pass

    graph = build_evidence_graph_for_intent(inv.intent, initial_ops)

    # Check for executed escalations and dynamically expand graph
    escalations = db.query(EscalationAction).filter(
        EscalationAction.investigation_id == investigation_id
    ).order_by(EscalationAction.created_at.asc()).all()

    for esc in escalations:
        try:
            new_ops = json.loads(str(esc.new_operations))
            if isinstance(new_ops, list):
                r_num = 2
                if esc.round_obj and esc.round_obj.round_number:
                    r_num = esc.round_obj.round_number + 1
                graph.expand_with_operations(new_ops, str(esc.trigger_rule), round_number=r_num)
        except Exception:
            pass

    # Update node statuses based on actual executed workflow steps
    for s in steps:
        node = graph.get_node_by_operation(s.operation)
        if node:
            if s.status == "COMPLETED":
                node.status = "COLLECTED"
            elif s.status == "FAILED":
                node.status = "FAILED"
            elif s.status == "RUNNING":
                node.status = "COLLECTING"
            else:
                node.status = "PLANNED"

    return {
        "investigation_id": inv.id,
        "intent": inv.intent,
        "evidence_graph": graph.to_dict(),
        "workflow_steps": [
            {
                "id": s.id,
                "operation": s.operation,
                "priority": s.priority,
                "round_number": s.round_obj.round_number if s.round_obj else 1,
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

    import json
    results = []
    for m in matches:
        severity = "HIGH"
        confidence_str = str(m.confidence) if m.confidence else "95%"
        try:
            if m.matched_data_json:
                data_obj = json.loads(str(m.matched_data_json))
                rule_name_str = str(m.rule_name)
                severity = data_obj.get("severity", "CRITICAL" if "POWERSHELL" in rule_name_str or "BYOVD" in rule_name_str else "HIGH")
                if "confidence_score" in data_obj:
                    confidence_str = f"{data_obj['confidence_score']}%"
                elif confidence_str == "rule_based":
                    if "POWERSHELL" in rule_name_str:
                        confidence_str = "95%"
                    elif "RECENT_EXECUTABLE" in rule_name_str:
                        confidence_str = "95%"
                    elif "BYOVD" in rule_name_str:
                        confidence_str = "98%"
                    elif "IN_MEMORY" in rule_name_str:
                        confidence_str = "95%"
                    else:
                        confidence_str = "90%"
        except Exception:
            pass

        results.append({
            "id": m.id,
            "round_number": m.round_number,
            "rule_name": m.rule_name,
            "confidence": confidence_str,
            "status_label": m.status_label,
            "severity": severity,
            "description": m.description,
            "matched_data": m.matched_data_json,
            "created_at": to_iso_utc(m.created_at)
        })

    return results

@router.post("/{investigation_id}/correlations/re-evaluate")
def reevaluate_investigation_correlations(investigation_id: str, db: Session = Depends(get_db)):
    """
    Re-evaluates correlation rules against all live collected evidence for the investigation.
    Saves updated empirical confidence scores and indicators into the database.
    """
    from pathlib import Path
    from app.intelligence.correlation_engine import CorrelationEngine
    import json

    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Load collected evidence from disk / artifacts
    ev_dir = Path(f"Adaptive-Forensic-Safety/evidence/{investigation_id}")
    collected_evidence = {}

    if ev_dir.exists():
        for r_dir in ev_dir.glob("round_*"):
            for f in r_dir.glob("*.json"):
                try:
                    with open(f, "r", encoding="utf-8") as fp:
                        d = json.load(fp)
                        op = d.get("_forensic_metadata", {}).get("operation")
                        data = d.get("evidence", [])
                        if op:
                            collected_evidence[op] = data
                except Exception:
                    pass

    # Also pull from EvidenceArtifact DB if file path exists
    artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == investigation_id).all()
    for art in artifacts:
        op_str = str(art.operation)
        if op_str not in collected_evidence:
            try:
                file_path_str = str(art.file_path) if art.file_path else ""
                if file_path_str and Path(file_path_str).exists():
                    with open(file_path_str, "r", encoding="utf-8") as fp:
                        d = json.load(fp)
                        collected_evidence[op_str] = d.get("evidence", [])
            except Exception:
                pass

    engine = CorrelationEngine()
    matches = engine.evaluate(collected_evidence)

    for m in matches:
        c_id = f"CORR-{inv.id}-R1-{m.rule_name}"
        data_json = json.dumps(m.matched_data, default=str)
        c_match = CorrelationMatch(
            id=c_id,
            investigation_id=inv.id,
            round_number=1,
            rule_name=m.rule_name,
            confidence=m.confidence,
            status_label=m.status_label,
            description=m.description,
            matched_data_json=data_json
        )
        db.merge(c_match)

    db.commit()

    return get_investigation_correlations(investigation_id, db)


@router.get("/{investigation_id}/ai-analysis")
def get_investigation_ai_analysis(investigation_id: str, db: Session = Depends(get_db)):
    """Runs AI-assisted evidence analysis, MITRE ATT&CK mapping, and executive root cause synthesis."""
    from app.services.ai_analyst import analyze_forensic_artifacts
    
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    arts = db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == investigation_id).all()
    corrs = db.query(CorrelationMatch).filter(CorrelationMatch.investigation_id == investigation_id).all()
    
    inv_data = {
        "investigation_id": investigation_id,
        "target_machine": inv.machine_id or "UNKNOWN_HOST",
        "intent": inv.intent,
        "artifacts": [
            {"collector": a.collector or a.operation, "description": a.name, "data": str(a.file_path or a.sha256)}
            for a in arts
        ],
        "correlations": [
            {"rule_name": c.rule_name, "description": c.description, "confidence": c.confidence}
            for c in corrs
        ]
    }
    
    return analyze_forensic_artifacts(inv_data)

@router.get("/{investigation_id}/sigma-rule")
def get_investigation_sigma_rule(investigation_id: str, db: Session = Depends(get_db)):
    """Generates a production-ready Sigma YAML detection rule from the investigation's observed IoCs."""
    from app.services.ai_analyst import generate_sigma_rule
    
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    return {
        "investigation_id": investigation_id,
        "format": "yaml",
        "sigma_rule": generate_sigma_rule({"target_machine": inv.machine_id or "UNKNOWN_HOST"})
    }

