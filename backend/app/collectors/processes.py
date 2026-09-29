from datetime import datetime, timezone
import psutil
from app.collectors.base import BaseCollector, CollectorResult

class ProcessListCollector(BaseCollector):
    name: str = "Process List Collector"
    operation: str = "PROCESS.LIST"
    description: str = "Collects snapshot of all running processes with PID, executable path, user, and resources."

    def collect(self, params: dict | None = None) -> CollectorResult:
        processes = []
        errors = 0
        limit = params.get("limit") if params else None

        for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'status']):
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username', 'create_time', 'status'])
                
                # Executable path with explicit permission handling
                try:
                    pinfo['exe'] = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    pinfo['exe'] = None

                # Memory usage
                try:
                    mem = proc.memory_info()
                    pinfo['memory_rss_bytes'] = mem.rss
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pinfo['memory_rss_bytes'] = 0

                # Convert create_time to UTC ISO format
                if pinfo.get('create_time'):
                    pinfo['create_time_iso'] = datetime.fromtimestamp(
                        pinfo['create_time'], tz=timezone.utc
                    ).isoformat()
                else:
                    pinfo['create_time_iso'] = None

                processes.append(pinfo)
                if limit and len(processes) >= limit:
                    break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                errors += 1
                continue
            except Exception:
                errors += 1
                continue

        # Sort by PID
        processes.sort(key=lambda x: x.get('pid', 0))

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS" if processes else "FAILED",
            data=processes,
            item_count=len(processes),
            metadata={"total_processes": len(processes), "access_denied_or_skipped": errors}
        )
