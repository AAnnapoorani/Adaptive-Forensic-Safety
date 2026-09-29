import json
import platform
import subprocess
from datetime import datetime, timezone
from app.collectors.base import BaseCollector, CollectorResult
from app.core.config import settings

class EventLogRecentCollector(BaseCollector):
    name: str = "Recent Event Log Collector"
    operation: str = "EVENTLOG.RECENT"
    description: str = "Safely captures recent system and security event log entries within a limited window."

    def collect(self, params: dict | None = None) -> CollectorResult:
        events = []
        limit = (params.get("limit") if params else None) or 15
        system = platform.system()

        if system == "Windows":
            # Attempt to query Windows Event Log safely using PowerShell
            try:
                # Use Get-WinEvent with JSON output for structured parsing
                ps_cmd = (
                    f"Get-WinEvent -FilterHashtable @{{LogName='System'}} -MaxEvents {limit} -ErrorAction SilentlyContinue | "
                    f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | "
                    f"ConvertTo-Json -Compress"
                )
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=8)
                
                if res.returncode == 0 and res.stdout.strip():
                    raw = json.loads(res.stdout.strip())
                    items = raw if isinstance(raw, list) else [raw]
                    for it in items:
                        tcreated = it.get("TimeCreated")
                        # Clean up PowerShell JSON date format /Date(1727...)/ if present
                        if tcreated and isinstance(tcreated, str) and "/Date(" in tcreated:
                            try:
                                epoch_ms = int(tcreated.split("(")[1].split(")")[0])
                                tcreated = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc).isoformat()
                            except Exception:
                                pass

                        events.append({
                            "timestamp": tcreated or datetime.utcnow().isoformat() + "Z",
                            "event_id": it.get("Id"),
                            "level": it.get("LevelDisplayName", "Information"),
                            "source": it.get("ProviderName", "System"),
                            "message": (it.get("Message") or "")[:200]
                        })
            except Exception as e:
                # Permission denied or timeout
                pass

        elif system == "Linux":
            try:
                cmd = ["journalctl", "-n", str(limit), "-o", "json"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if line.strip():
                            parsed = json.loads(line)
                            events.append({
                                "timestamp": parsed.get("__REALTIME_TIMESTAMP") or datetime.utcnow().isoformat(),
                                "event_id": parsed.get("MESSAGE_ID", "LINUX_JOURNAL"),
                                "level": parsed.get("PRIORITY", "INFO"),
                                "source": parsed.get("_SYSTEMD_UNIT", "systemd"),
                                "message": parsed.get("MESSAGE", "")[:200]
                            })
            except Exception:
                pass

        # If no events could be captured due to unprivileged user access or environment:
        # Provide clean, transparent status
        if not events:
            if settings.DEMO_MODE:
                events = [
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "event_id": 7036,
                        "level": "Information",
                        "source": "Service Control Manager",
                        "message": "The Background Intelligent Transfer Service entered the running state. (SYNTHETIC DEMO DATA)"
                    }
                ]
                status = "SUCCESS"
            else:
                status = "PARTIALLY_COMPLETED"
        else:
            status = "SUCCESS"

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status=status,
            data=events,
            item_count=len(events),
            metadata={
                "platform": system,
                "requested_limit": limit,
                "captured_count": len(events)
            }
        )
