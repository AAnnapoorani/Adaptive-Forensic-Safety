import json
import uuid
from typing import Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.investigation import Investigation, InvestigationRound
from app.models.workflow import WorkflowStep
from app.models.evidence import EvidenceArtifact
from app.models.execution import CorrelationMatch, EscalationAction, ExecutionLog
from app.models.machine import Machine


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

from app.jocky.compiler import JockyCompiler
from app.intelligence.intent_engine import IntentEngine
from app.intelligence.evidence_graph import build_evidence_graph_for_intent, EvidenceRequirementGraph
from app.intelligence.workflow_planner import WorkflowCompiler
from app.collectors.registry import get_collector
from app.services.evidence_service import EvidenceService
from app.intelligence.correlation_engine import CorrelationEngine
from app.intelligence.escalation_rules import AdaptiveEscalationEngine
from app.services.timeline_service import TimelineService

class InvestigationService:
    @staticmethod
    def create_investigation(
        db: Session,
        intent: str = "suspicious_network_activity",
        script: str | None = None,
        machine_id: str | None = None
    ) -> Investigation:
        """Create a new investigation record and initialize Round 1."""
        # Find default machine if not supplied
        if not machine_id:
            m = db.query(Machine).first()
            machine_id = m.id if m else "MACHINE-LOCAL"

        # Sequential ID
        inv_count = db.query(Investigation).count()
        inv_id = f"INV-{_utc_now().strftime('%Y%m%d')}-{inv_count + 1:03d}"

        # If script provided, compile and parse intent
        parsed_intent = intent
        total_rounds = settings.MAX_ROUNDS
        if script and script.strip():
            ast_root, ir = JockyCompiler.compile(script)
            if ir.intent:
                parsed_intent = ir.intent
            if ir.round_limit:
                total_rounds = ir.round_limit
            if ir.target_id:
                m = db.query(Machine).filter((Machine.id == ir.target_id) | (Machine.hostname == ir.target_id)).first()
                if m:
                    machine_id = m.id
                else:
                    machine_id = ir.target_id
            for ins in ir.instructions:
                if ins.kind == "INVESTIGATION":
                    parsed_intent = ins.parameters.get("intent", parsed_intent)
                    break

        inv = Investigation(
            id=inv_id,
            intent=parsed_intent,
            script=script,
            machine_id=machine_id,
            status="CREATED",
            current_round=1,
            total_rounds=total_rounds,
            start_time=_utc_now()
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        # Log creation
        db.add(ExecutionLog(
            id=f"LOG-{uuid.uuid4().hex[:8]}",
            investigation_id=inv.id,
            component="INVESTIGATION_SERVICE",
            level="INFO",
            message=f"Investigation created with intent: '{parsed_intent}' on machine: '{machine_id}'"
        ))
        db.commit()

        return inv

    @staticmethod
    def preview_script(script: str | None = None, intent: str = "suspicious_network_activity") -> dict:
        """Compile and preview Evidence DAG and planned workflow without creating an investigation in DB."""
        intent_engine = IntentEngine()
        parsed_intent = intent
        initial_ops = intent_engine.resolve_initial_operations(intent)

        tokens_list = []
        ir_dict = {}

        if script and script.strip():
            inspection = JockyCompiler.inspect(script)
            parsed_intent = inspection["parsed_intent"]
            tokens_list = inspection["tokens"]
            ir_dict = inspection["ir"]
            initial_ops = inspection["planned_operations"]
            graph_dict = inspection["evidence_graph"]
            workflow_dict = inspection["workflow"]
        else:
            graph = build_evidence_graph_for_intent(parsed_intent, initial_ops)
            workflow = WorkflowCompiler.compile(graph, investigation_id="INV-PREVIEW", round_number=1)
            graph_dict = graph.to_dict()
            workflow_dict = workflow.to_dict()

        return {
            "intent": parsed_intent,
            "round": 1,
            "tokens": tokens_list,
            "ir": ir_dict,
            "initial_operations": initial_ops,
            "evidence_graph": graph_dict,
            "workflow": workflow_dict
        }

    @staticmethod
    def preview_investigation(db: Session, investigation_id: str) -> dict:
        """Preview initial Evidence Requirement Graph and Compiled Workflow prior to execution."""
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")

        intent_engine = IntentEngine()
        initial_ops = intent_engine.resolve_initial_operations(inv.intent)

        # If user supplied a specific manual script, incorporate any manual operations
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

        # Build Graph and Compile Workflow
        graph = build_evidence_graph_for_intent(inv.intent, initial_ops)
        workflow = WorkflowCompiler.compile(graph, investigation_id=inv.id, round_number=1)

        return {
            "investigation_id": inv.id,
            "intent": inv.intent,
            "round": 1,
            "initial_operations": initial_ops,
            "evidence_graph": graph.to_dict(),
            "workflow": workflow.to_dict()
        }

    @staticmethod
    def execute_investigation(db: Session, investigation_id: str, demo_mode: bool = False) -> dict:
        """
        Execute full end-to-end investigation with:
        Round 1 collection -> Correlation -> Adaptive Escalation -> Round 2 collection -> Final Synthesis.
        """
        is_demo = demo_mode or settings.DEMO_MODE

        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")

        inv.status = "IN_PROGRESS"
        db.commit()

        intent_engine = IntentEngine()
        initial_ops = intent_engine.resolve_initial_operations(inv.intent)

        # Build initial Evidence Requirement Graph
        graph = build_evidence_graph_for_intent(inv.intent, initial_ops)

        round_limit = inv.total_rounds if (inv.total_rounds and inv.total_rounds > 0) else settings.MAX_ROUNDS
        correlation_engine = CorrelationEngine()
        escalation_engine = AdaptiveEscalationEngine(max_rounds=round_limit)

        executed_operations: set[str] = set()
        triggered_rules: set[str] = set()
        all_collected_evidence: dict[str, Any] = {}

        current_round = 1
        rounds_executed = []

        matched_rules_set: set[str] = set()

        while current_round <= round_limit:
            # 1. Create InvestigationRound record
            round_record_id = f"RND-{inv.id}-{current_round:02d}"
            trigger_reason = (
                "Initial investigation requirement" if current_round == 1
                else f"Adaptive escalation triggered by rule evaluation"
            )
            round_obj = InvestigationRound(
                id=round_record_id,
                investigation_id=inv.id,
                round_number=current_round,
                trigger_reason=trigger_reason,
                status="EXECUTING",
                started_at=_utc_now()
            )
            round_obj = db.merge(round_obj)
            db.commit()

            # 2. Compile Workflow for this round
            workflow = WorkflowCompiler.compile(
                graph=graph,
                investigation_id=inv.id,
                round_number=current_round,
                already_executed_ops=executed_operations
            )

            round_step_records = []
            for planned_step in workflow.steps:
                step_obj = WorkflowStep(
                    id=f"STEP-{inv.id}-R{current_round}-{planned_step.operation.replace('.', '_')}",
                    investigation_id=inv.id,
                    round_id=round_obj.id,
                    operation=planned_step.operation,
                    priority=planned_step.priority,
                    status="RUNNING",
                    start_time=_utc_now()
                )
                step_obj = db.merge(step_obj)
                db.commit()

                # Execute Collector (or Deterministic Synthetic Evidence if is_demo)
                collector = get_collector(planned_step.operation)
                if is_demo:
                    from app.intelligence.demo_dataset import get_demo_evidence
                    data = get_demo_evidence(planned_step.operation)
                    item_count = len(data) if isinstance(data, list) else 1
                    collector_name = collector.name if collector else f"{planned_step.operation} Demo Collector"
                    all_collected_evidence[planned_step.operation] = data

                    artifact = EvidenceService.save_evidence(
                        db=db,
                        investigation_id=inv.id,
                        round_number=current_round,
                        operation=planned_step.operation,
                        collector_name=collector_name,
                        data=data,
                        reason=planned_step.reason,
                        machine_id=inv.machine_id,
                        step_id=str(step_obj.id),
                        is_synthetic=True
                    )

                    step_obj.status = "COMPLETED"
                    step_obj.end_time = _utc_now()
                    step_obj.result_summary = f"[DEMO] Collected {item_count} items. Artifact ID: {artifact.id}"
                    graph.update_node_status(f"node_{planned_step.operation.lower().replace('.', '_')}", "COLLECTED")
                elif collector:
                    try:
                        res = collector.collect()
                        all_collected_evidence[planned_step.operation] = res.data
                        
                        artifact = EvidenceService.save_evidence(
                            db=db,
                            investigation_id=inv.id,
                            round_number=current_round,
                            operation=planned_step.operation,
                            collector_name=collector.name,
                            data=res.data,
                            reason=planned_step.reason,
                            machine_id=inv.machine_id,
                            step_id=str(step_obj.id),
                            is_synthetic=False
                        )

                        step_obj.status = "COMPLETED"
                        step_obj.end_time = _utc_now()
                        step_obj.result_summary = f"Collected {res.item_count} items. Artifact ID: {artifact.id}"
                        graph.update_node_status(f"node_{planned_step.operation.lower().replace('.', '_')}", "COLLECTED")
                    except Exception as e:
                        error_payload = {
                            "collector": planned_step.operation,
                            "status": "error",
                            "error": str(e),
                            "timestamp": _utc_now().isoformat(),
                            "partial": True
                        }
                        all_collected_evidence[planned_step.operation] = error_payload
                        try:
                            EvidenceService.save_evidence(
                                db=db,
                                investigation_id=inv.id,
                                round_number=current_round,
                                operation=planned_step.operation,
                                collector_name=collector.name if collector else planned_step.operation,
                                data=error_payload,
                                reason=f"Collector execution failure: {str(e)}",
                                machine_id=inv.machine_id,
                                step_id=str(step_obj.id),
                                is_synthetic=False
                            )
                        except Exception:
                            pass
                        step_obj.status = "FAILED"
                        step_obj.end_time = _utc_now()
                        step_obj.error_message = str(e)
                        step_obj.result_summary = f"Error: {str(e)}"
                        graph.update_node_status(f"node_{planned_step.operation.lower().replace('.', '_')}", "FAILED")
                else:
                    step_obj.status = "FAILED"
                    step_obj.end_time = _utc_now()
                    step_obj.error_message = f"Collector {planned_step.operation} not found in registry"


                db.commit()
                executed_operations.add(planned_step.operation)
                round_step_records.append(step_obj)

            round_obj.status = "COMPLETED"
            round_obj.completed_at = _utc_now()
            db.commit()
            rounds_executed.append(current_round)

            # 3. Evidence Correlation Analysis
            matches = correlation_engine.evaluate(all_collected_evidence)
            for m in matches:
                if m.rule_name in matched_rules_set:
                    continue
                matched_rules_set.add(m.rule_name)
                # Save CorrelationMatch record
                c_id = f"CORR-{inv.id}-R{current_round}-{m.rule_name}"
                c_match = CorrelationMatch(
                    id=c_id,
                    investigation_id=inv.id,
                    round_id=round_obj.id,
                    round_number=current_round,
                    rule_name=m.rule_name,
                    confidence=m.confidence,
                    status_label=m.status_label,
                    description=m.description,
                    matched_data_json=json.dumps(m.matched_data, default=str)
                )
                db.merge(c_match)
            db.commit()

            # 4. Adaptive Escalation Decision
            decision = escalation_engine.evaluate_escalation(
                current_round=current_round,
                matches=matches,
                executed_operations=executed_operations,
                triggered_rules=triggered_rules
            )

            if decision.should_escalate and decision.new_operations:
                # Record EscalationAction
                esc_id = f"ESC-{inv.id}-R{current_round}-{decision.trigger_rule}"
                esc_action = EscalationAction(
                    id=esc_id,
                    investigation_id=inv.id,
                    round_id=round_obj.id,
                    trigger_rule=decision.trigger_rule or "ANOMALY",
                    new_operations=json.dumps(decision.new_operations),
                    status="TRIGGERED"
                )
                db.merge(esc_action)
                db.commit()

                # Mark rule as triggered
                if decision.trigger_rule:
                    triggered_rules.add(decision.trigger_rule)

                # Dynamically expand Evidence Requirement Graph
                graph.expand_with_operations(
                    new_operations=decision.new_operations,
                    trigger_rule=decision.trigger_rule or "CORRELATION_RULE",
                    round_number=decision.round_number
                )

                # Advance to next round
                current_round = decision.round_number
                inv.current_round = current_round
                inv.total_rounds = current_round
                db.commit()
            else:
                # No further escalation needed
                break

        # 5. Final Synthesis: Unified Timeline, Chain Manifest & Evidence Integrity Check
        timeline_events = TimelineService.generate_timeline(db, inv.id, inv.machine_id)
        from app.services.chain_service import ChainService
        from app.services.verifier_service import VerifierService
        chain_manifest = ChainService.update_chain_manifest(db, inv.id)
        chain_verification = VerifierService.verify_investigation_chain(db, inv.id)
        integrity_check = EvidenceService.verify_all_investigation_evidence(db, inv.id)

        # 6. Finalize Investigation Status
        inv.status = "COMPLETED"
        inv.end_time = _utc_now()
        inv.total_rounds = len(rounds_executed)
        inv.summary = (
            f"Investigation finished with {len(rounds_executed)} rounds. "
            f"Collected {integrity_check['total_artifacts']} artifacts ({integrity_check['valid_count']} verified). "
            f"Cryptographic hash chain status: {chain_verification['result']} (tip: {chain_manifest.chain_tip[:12]}...). "
            f"Synthesized {len(timeline_events)} chronological events."
        )
        db.commit()
        db.refresh(inv)

        return {
            "investigation_id": inv.id,
            "status": inv.status,
            "rounds_executed": len(rounds_executed),
            "artifacts_collected": integrity_check["total_artifacts"],
            "timeline_events_count": len(timeline_events),
            "integrity_verified": integrity_check["all_valid"],
            "chain_verified": chain_verification["verified"],
            "chain_tip": chain_manifest.chain_tip,
            "signer_key_id": chain_manifest.key_id,
            "summary": inv.summary
        }

