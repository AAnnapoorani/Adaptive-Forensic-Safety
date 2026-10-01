"""
JOCKY Autonomous Incident Auto-Triage Engine (Phase 21)

Monitors incoming endpoint telemetry streams, process tables, and forensic events.
When high-confidence anomaly thresholds are breached (sustained CPU > 90% + critical process,
BYOVD driver detection, unbacked memory injection, or high-severity forensic alerts),
the engine autonomously synthesizes an investigation ticket and immediately locks the host
system state into the Ed25519 cryptographic hash chain without waiting for manual human triage.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from app.core.sse import sse_manager
from app.services.investigation_service import InvestigationService

logger = logging.getLogger("jocky.auto_triage")

# In-memory cooldown tracking: { machine_id: last_auto_triage_timestamp }
_COOLDOWN_MAP: dict[str, float] = {}
COOLDOWN_SECONDS = 180.0  # 3 minutes cooldown between auto-dispatched investigations per machine


class AutoTriageService:
    @staticmethod
    def evaluate_telemetry(
        db: Session,
        machine_id: str,
        metrics: Any,
        processes: list[dict] | None = None,
        events: list[dict] | None = None
    ) -> dict[str, Any] | None:
        """
        Evaluate live telemetry for anomalous threats and dispatch auto-investigation if thresholds trigger.
        Returns details of the created investigation, or None if no threshold breached or on cooldown.
        """
        now = time.time()
        last_triage = _COOLDOWN_MAP.get(machine_id, 0.0)
        if now - last_triage < COOLDOWN_SECONDS:
            return None

        trigger_reasons: list[str] = []
        selected_intent = "system_compromise"

        # 1. Evaluate Process Threat Levels & In-Memory Indicators
        if processes:
            for p in processes:
                threat = str(p.get("threat_level") or "").upper()
                pname = str(p.get("name") or "").lower()
                rules = p.get("matched_rules") or []

                if threat == "CRITICAL":
                    trigger_reasons.append(f"Critical process observed: {pname} (PID: {p.get('pid')})")
                    if any("memory" in str(r).lower() or "injection" in str(r).lower() for r in rules):
                        selected_intent = "memory_injection_hunt"
                    elif any("byovd" in str(r).lower() or "driver" in str(r).lower() for r in rules):
                        selected_intent = "byovd_detection"
                    break
                elif threat == "HIGH" and len(trigger_reasons) < 2:
                    trigger_reasons.append(f"High-threat process observed: {pname}")

        # 2. Evaluate Forensic Events
        if events:
            for e in events:
                sev = str(e.get("severity") or "").upper()
                desc = str(e.get("description") or "").lower()
                etype = str(e.get("event_type") or "").lower()

                if sev in ("CRITICAL", "HIGH"):
                    trigger_reasons.append(f"High-severity forensic alert: {e.get('event_type')} - {e.get('description')}")
                    if "byovd" in desc or "driver" in desc or "byovd" in etype:
                        selected_intent = "byovd_detection"
                    elif "memory" in desc or "injection" in desc or "hollowing" in desc:
                        selected_intent = "memory_injection_hunt"
                    elif "network" in desc or "socket" in desc or "beacon" in desc:
                        selected_intent = "suspicious_network_activity"
                    break

        # 3. Evaluate Resource Anomaly (Sustained High CPU + Heavy Processes)
        cpu_pct = getattr(metrics, "cpu_percent", 0.0) if metrics else 0.0
        if cpu_pct >= 92.0 and trigger_reasons:
            trigger_reasons.append(f"Elevated host CPU threshold crossed: {cpu_pct:.1f}%")

        # If no critical condition satisfied, exit
        if not trigger_reasons:
            return None

        # Breach detected! Record cooldown and create investigation
        _COOLDOWN_MAP[machine_id] = now
        combined_reason = " | ".join(trigger_reasons)

        try:
            inv = InvestigationService.create_investigation(
                db=db,
                intent=selected_intent,
                script=f"# Autonomous Incident Auto-Triage\n# Trigger: {combined_reason}\nINVESTIGATE {selected_intent}",
                machine_id=machine_id
            )

            # Broadcast auto-triage notification to connected SOC analysts
            sse_manager.broadcast_sync("auto_triage_incident_created", {
                "investigation_id": inv.id,
                "machine_id": machine_id,
                "intent": selected_intent,
                "reason": combined_reason,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            logger.warning(
                f"[AUTO-TRIAGE] Dispatched emergency investigation {inv.id} on {machine_id}: {combined_reason}"
            )

            return {
                "triggered": True,
                "investigation_id": inv.id,
                "intent": selected_intent,
                "reason": combined_reason,
                "machine_id": machine_id
            }
        except Exception as ex:
            logger.error(f"[AUTO-TRIAGE] Failed to create auto-triage investigation: {ex}")
            return None
