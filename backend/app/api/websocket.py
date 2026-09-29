"""
JOCKY Real-Time WebSocket streaming endpoint

Streams live investigation execution events to the frontend as they happen:
  - Collector start / completion with live data counts
  - Correlation rule matches in real-time
  - Adaptive escalation triggers
  - Memory and driver scan results as they arrive

Uses FastAPI WebSocket + asyncio.  The backend runs the blocking
investigation work in a thread pool and pushes events via the websocket.

Endpoint: ws://localhost:8000/api/ws/investigations/{investigation_id}/stream
"""

import asyncio
import json
import platform
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.investigation import Investigation
from app.collectors.registry import get_collector, COLLECTOR_REGISTRY
from app.intelligence.correlation_engine import CorrelationEngine
from app.intelligence.intent_engine import IntentEngine
from app.jocky.polymorphic import PolymorphicEngine, PayloadEncryptor

router = APIRouter(prefix="/ws", tags=["Real-Time WebSocket Streams"])


def _ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


async def _send(ws: WebSocket, event_type: str, payload: dict) -> bool:
    """Send a JSON event to the frontend websocket client. Returns False if disconnected."""
    if ws.client_state == WebSocketState.DISCONNECTED:
        return False
    try:
        await ws.send_json({"type": event_type, "ts": _ts(), **payload})
        return True
    except (WebSocketDisconnect, RuntimeError, ConnectionResetError, asyncio.CancelledError):
        return False
    except Exception:
        return False


@router.websocket("/investigations/{investigation_id}/stream")
async def stream_investigation(websocket: WebSocket, investigation_id: str):
    """
    WebSocket endpoint that streams real-time investigation execution events.
    The frontend connects here immediately after launching an investigation;
    all collector progress, correlations, and escalations are pushed live.
    """
    await websocket.accept()

    try:
        if not await _send(websocket, "CONNECTED", {
            "investigation_id": investigation_id,
            "message": "Real-time stream established"
        }):
            return

        # Poll DB until investigation is done, forwarding status changes
        prev_status = None
        prev_artifact_count = 0
        timeout = 300  # 5-minute watchdog
        elapsed = 0

        while elapsed < timeout:
            if websocket.client_state == WebSocketState.DISCONNECTED:
                break

            db: Session = SessionLocal()
            try:
                from app.models.evidence import EvidenceArtifact
                from app.models.execution import CorrelationMatch
                from app.models.workflow import WorkflowStep

                inv = db.query(Investigation).filter(
                    Investigation.id == investigation_id
                ).first()

                if not inv:
                    await _send(websocket, "ERROR", {"message": f"Investigation {investigation_id} not found"})
                    break

                # Status change notification
                if inv.status != prev_status:
                    if not await _send(websocket, "STATUS_CHANGE", {
                        "investigation_id": investigation_id,
                        "status": inv.status,
                        "round": inv.current_round
                    }):
                        break
                    prev_status = inv.status

                # New artifacts notification
                artifacts = db.query(EvidenceArtifact).filter(
                    EvidenceArtifact.investigation_id == investigation_id
                ).all()
                if len(artifacts) > prev_artifact_count:
                    new_arts = artifacts[prev_artifact_count:]
                    disconnected = False
                    for art in new_arts:
                        if not await _send(websocket, "ARTIFACT_COLLECTED", {
                            "artifact_id": art.id,
                            "operation": art.operation,
                            "collector_name": art.collector_name,
                            "item_count": art.item_count,
                            "is_synthetic": art.is_synthetic,
                            "round": art.round_number,
                            "sha256": art.sha256_hash,
                            "collected_at": art.collected_at.isoformat() if art.collected_at else None
                        }):
                            disconnected = True
                            break
                    if disconnected:
                        break
                    prev_artifact_count = len(artifacts)

                # Correlation matches
                matches = db.query(CorrelationMatch).filter(
                    CorrelationMatch.investigation_id == investigation_id
                ).all()
                if matches:
                    if not await _send(websocket, "CORRELATIONS", {
                        "count": len(matches),
                        "rules": [{"rule": m.rule_name, "severity": m.severity, "description": m.description} for m in matches]
                    }):
                        break

                # Running workflow steps
                steps = db.query(WorkflowStep).filter(
                    WorkflowStep.investigation_id == investigation_id,
                    WorkflowStep.status == "RUNNING"
                ).all()
                if steps:
                    if not await _send(websocket, "STEPS_RUNNING", {
                        "running": [s.operation for s in steps]
                    }):
                        break

                # Done?
                if inv.status in ("COMPLETED", "FAILED"):
                    await _send(websocket, "INVESTIGATION_COMPLETE", {
                        "status": inv.status,
                        "total_artifacts": len(artifacts),
                        "total_correlations": len(matches),
                        "rounds": inv.total_rounds
                    })
                    break

            finally:
                db.close()

            try:
                await asyncio.sleep(1.5)
            except (asyncio.CancelledError, Exception):
                break
            elapsed += 1.5

    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as e:
        try:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await _send(websocket, "ERROR", {"message": str(e)})
        except Exception:
            pass


@router.websocket("/live/system")
async def stream_live_system(websocket: WebSocket):
    """
    Continuous real-time system telemetry stream (no investigation required).
    Pushes live system metrics, network connections, and process counts every 3s.
    Used by the Evasion Lab Live Monitor panel.
    """
    await websocket.accept()

    try:
        if not await _send(websocket, "CONNECTED", {
            "message": "Live system telemetry stream active",
            "platform": platform.system()
        }):
            return

        system_collector = get_collector("SYSTEM.INFO")
        network_collector = get_collector("NETWORK.CONNECTIONS")
        process_collector = get_collector("PROCESS.LIST")

        tick = 0
        while True:
            if websocket.client_state == WebSocketState.DISCONNECTED:
                break
            tick += 1

            # System metrics every tick
            if system_collector:
                try:
                    sys_res = await asyncio.get_event_loop().run_in_executor(
                        None, system_collector.collect
                    )
                    sent = await _send(websocket, "SYSTEM_METRICS", {
                        "tick": tick,
                        "data": sys_res.data,
                        "status": sys_res.status
                    })
                    if not sent:
                        break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not await _send(websocket, "SYSTEM_METRICS_ERROR", {"error": str(e)}):
                        break

            # Network connections every 2 ticks (6s)
            if network_collector and tick % 2 == 0:
                try:
                    net_res = await asyncio.get_event_loop().run_in_executor(
                        None, network_collector.collect
                    )
                    external = [c for c in (net_res.data or []) if c.get("is_external")]
                    sent = await _send(websocket, "NETWORK_SNAPSHOT", {
                        "tick": tick,
                        "total_connections": net_res.item_count,
                        "external_count": len(external),
                        "external_connections": external[:10],
                        "status": net_res.status
                    })
                    if not sent:
                        break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not await _send(websocket, "NETWORK_ERROR", {"error": str(e)}):
                        break

            # Process count every tick
            if process_collector:
                try:
                    proc_res = await asyncio.get_event_loop().run_in_executor(
                        None, process_collector.collect
                    )
                    sent = await _send(websocket, "PROCESS_COUNT", {
                        "tick": tick,
                        "count": proc_res.item_count,
                        "status": proc_res.status
                    })
                    if not sent:
                        break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not await _send(websocket, "PROCESS_ERROR", {"error": str(e)}):
                        break

            try:
                await asyncio.sleep(3)
            except (asyncio.CancelledError, Exception):
                break

    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as e:
        try:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await _send(websocket, "ERROR", {"message": str(e)})
        except Exception:
            pass


@router.websocket("/live/evasion")
async def stream_live_evasion(websocket: WebSocket):
    """
    Real-time evasion telemetry stream for the Evasion Lab page.
    Pushes live driver scans and memory injection checks every 10s.
    """
    await websocket.accept()

    driver_collector = get_collector("DRIVERS.LIST")
    memory_collector = get_collector("MEMORY.ANALYSIS")

    try:
        if not await _send(websocket, "CONNECTED", {
            "message": "Evasion lab real-time stream active",
            "capabilities": {
                "drivers": driver_collector is not None,
                "memory": memory_collector is not None,
                "platform": platform.system()
            }
        }):
            return

        tick = 0
        while True:
            if websocket.client_state == WebSocketState.DISCONNECTED:
                break
            tick += 1

            # Drivers scan
            if driver_collector:
                try:
                    drv_res = await asyncio.get_event_loop().run_in_executor(
                        None, driver_collector.collect
                    )
                    drivers = drv_res.data or []
                    byovd = [d for d in drivers if isinstance(d, dict) and d.get("is_byovd_known_vulnerable")]
                    sent = await _send(websocket, "DRIVER_SCAN", {
                        "tick": tick,
                        "total_drivers": len(drivers),
                        "byovd_count": len(byovd),
                        "byovd_drivers": byovd,
                        "status": drv_res.status,
                        "collection_method": drv_res.metadata.get("collection_method", "ctypes Win32")
                    })
                    if not sent:
                        break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not await _send(websocket, "DRIVER_SCAN_ERROR", {"error": str(e)}):
                        break

            # Memory scan every 2 ticks
            if memory_collector and tick % 2 == 0:
                try:
                    mem_res = await asyncio.get_event_loop().run_in_executor(
                        None, memory_collector.collect
                    )
                    regions = mem_res.data or []
                    high = [r for r in regions if isinstance(r, dict) and r.get("severity") == "HIGH"]
                    sent = await _send(websocket, "MEMORY_SCAN", {
                        "tick": tick,
                        "suspicious_regions": len(regions),
                        "high_severity": len(high),
                        "regions": regions[:5],
                        "status": mem_res.status,
                        "scanned_processes": mem_res.metadata.get("scanned_processes", 0)
                    })
                    if not sent:
                        break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not await _send(websocket, "MEMORY_SCAN_ERROR", {"error": str(e)}):
                        break

            try:
                await asyncio.sleep(10)
            except (asyncio.CancelledError, Exception):
                break

    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as e:
        try:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await _send(websocket, "ERROR", {"message": str(e)})
        except Exception:
            pass

