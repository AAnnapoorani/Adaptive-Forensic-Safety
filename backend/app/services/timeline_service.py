import json
from typing import Any
from datetime import datetime, timezone
from pathlib import Path
from dateutil import parser as dt_parser
from sqlalchemy.orm import Session
from app.models.timeline import TimelineEvent
from app.models.evidence import EvidenceArtifact
from app.models.investigation import InvestigationRound

def parse_iso_or_fallback(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val.replace(tzinfo=None) if val.tzinfo else val
    if isinstance(val, (int, float)):
        return datetime.utcfromtimestamp(val)
    if isinstance(val, str) and val.strip():
        try:
            dt = dt_parser.parse(val)
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except Exception:
            pass
    return datetime.utcnow()

class TimelineService:
    @staticmethod
    def generate_timeline(db: Session, investigation_id: str, machine_id: str) -> list[TimelineEvent]:
        """
        Synthesize a unified, chronologically sorted forensic timeline
        from all collected artifacts and workflow round milestones.
        """
        # Delete existing timeline events for this investigation to prevent duplicate rebuilds
        db.query(TimelineEvent).filter(TimelineEvent.investigation_id == investigation_id).delete()
        db.commit()

        events_to_create = []

        # 1. Add Investigation Round Milestones
        rounds = db.query(InvestigationRound).filter(
            InvestigationRound.investigation_id == investigation_id
        ).all()
        for r in rounds:
            events_to_create.append(TimelineEvent(
                id=f"TL-RND-{r.id}",
                investigation_id=investigation_id,
                timestamp=parse_iso_or_fallback(r.started_at),
                event_type="WORKFLOW_ROUND_STARTED",
                description=f"Investigation Round {r.round_number} initiated. Trigger: {r.trigger_reason}",
                source="INVESTIGATION_ENGINE",
                machine_id=machine_id,
                round_number=r.round_number,
                details_json=json.dumps({"round": r.round_number, "reason": r.trigger_reason})
            ))
            if r.completed_at:
                events_to_create.append(TimelineEvent(
                    id=f"TL-RND-END-{r.id}",
                    investigation_id=investigation_id,
                    timestamp=parse_iso_or_fallback(r.completed_at),
                    event_type="WORKFLOW_ROUND_COMPLETED",
                    description=f"Investigation Round {r.round_number} completed.",
                    source="INVESTIGATION_ENGINE",
                    machine_id=machine_id,
                    round_number=r.round_number,
                    details_json=json.dumps({"round": r.round_number})
                ))

        # 2. Extract events from Evidence Artifacts on disk
        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id
        ).all()

        for art in artifacts:
            try:
                p = Path(art.file_path)
                if not p.is_file():
                    continue

                with open(p, "r", encoding="utf-8") as f:
                    payload = json.load(f)

                data = payload.get("evidence", [])
                round_num = art.round_number

                # PROCESS.LIST -> PROCESS_CREATED
                if art.operation == "PROCESS.LIST" and isinstance(data, list):
                    for idx, proc in enumerate(data[:40]):  # Cap sample to maintain responsive timeline
                        raw_ts = proc.get("create_time_iso")
                        if raw_ts:
                            ts = parse_iso_or_fallback(raw_ts)
                            events_to_create.append(TimelineEvent(
                                id=f"TL-PROC-{art.id}-{idx}",
                                investigation_id=investigation_id,
                                timestamp=ts,
                                event_type="PROCESS_CREATED",
                                description=f"Process spawned: {proc.get('name')} (PID: {proc.get('pid')}, User: {proc.get('username') or 'N/A'})",
                                source="PROCESS.LIST",
                                machine_id=machine_id,
                                round_number=round_num,
                                details_json=json.dumps({"pid": proc.get("pid"), "exe": proc.get("exe")})
                            ))

                # NETWORK.CONNECTIONS -> NETWORK_CONNECTION
                elif art.operation == "NETWORK.CONNECTIONS" and isinstance(data, list):
                    for idx, conn in enumerate(data[:40]):
                        if conn.get("remote_address"):
                            events_to_create.append(TimelineEvent(
                                id=f"TL-NET-{art.id}-{idx}",
                                investigation_id=investigation_id,
                                timestamp=parse_iso_or_fallback(art.collected_at),
                                event_type="NETWORK_SOCKET_ACTIVE",
                                description=f"Network Socket: {conn.get('process_name') or 'PID ' + str(conn.get('pid'))} connected {conn.get('local_address')}:{conn.get('local_port')} -> {conn.get('remote_address')}:{conn.get('remote_port')} ({conn.get('status')})",
                                source="NETWORK.CONNECTIONS",
                                machine_id=machine_id,
                                round_number=round_num,
                                details_json=json.dumps(conn)
                            ))

                # FILES.RECENT -> FILE_MODIFIED
                elif art.operation == "FILES.RECENT" and isinstance(data, list):
                    for idx, file_item in enumerate(data[:30]):
                        raw_ts = file_item.get("modified_time") or file_item.get("created_time")
                        ts = parse_iso_or_fallback(raw_ts)
                        events_to_create.append(TimelineEvent(
                            id=f"TL-FILE-{art.id}-{idx}",
                            investigation_id=investigation_id,
                            timestamp=ts,
                            event_type="FILE_MODIFIED",
                            description=f"File activity: {file_item.get('filename')} ({file_item.get('size_bytes')} bytes) in monitored directory",
                            source="FILES.RECENT",
                            machine_id=machine_id,
                            round_number=round_num,
                            details_json=json.dumps(file_item)
                        ))

                # EVENTLOG.RECENT -> EVENT_LOG
                elif art.operation == "EVENTLOG.RECENT" and isinstance(data, list):
                    for idx, log_item in enumerate(data[:25]):
                        raw_ts = log_item.get("timestamp")
                        ts = parse_iso_or_fallback(raw_ts)
                        events_to_create.append(TimelineEvent(
                            id=f"TL-LOG-{art.id}-{idx}",
                            investigation_id=investigation_id,
                            timestamp=ts,
                            event_type="SYSTEM_EVENT_LOG",
                            description=f"Event {log_item.get('event_id')} [{log_item.get('level')}]: {log_item.get('message')}",
                            source="EVENTLOG.RECENT",
                            machine_id=machine_id,
                            round_number=round_num,
                            details_json=json.dumps(log_item)
                        ))

            except Exception:
                continue

        # Sort all timeline events chronologically
        events_to_create.sort(key=lambda e: e.timestamp)

        # Batch insert
        for ev in events_to_create:
            db.add(ev)
        db.commit()

        return events_to_create

    @staticmethod
    def get_timeline_events(db: Session, investigation_id: str) -> list[TimelineEvent]:
        """Fetch timeline events ordered chronologically."""
        return db.query(TimelineEvent).filter(
            TimelineEvent.investigation_id == investigation_id
        ).order_by(TimelineEvent.timestamp.asc()).all()
