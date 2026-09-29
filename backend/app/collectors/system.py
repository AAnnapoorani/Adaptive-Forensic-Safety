import getpass
import platform
import socket
from datetime import datetime, timezone
import psutil
from app.collectors.base import BaseCollector, CollectorResult

class SystemInfoCollector(BaseCollector):
    name: str = "System Information Collector"
    operation: str = "SYSTEM.INFO"
    description: str = "Collects OS, architecture, hardware metrics, boot time, and active user."

    def collect(self, params: dict | None = None) -> CollectorResult:
        try:
            boot_time_ts = psutil.boot_time()
            boot_time_dt = datetime.fromtimestamp(boot_time_ts, tz=timezone.utc).isoformat()
            uptime_seconds = int(datetime.now(tz=timezone.utc).timestamp() - boot_time_ts)
            
            mem = psutil.virtual_memory()
            
            try:
                current_user = getpass.getuser()
            except Exception:
                current_user = "unknown"

            system_data = {
                "hostname": socket.gethostname(),
                "operating_system": platform.system(),
                "os_version": platform.version(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "cpu_logical_cores": psutil.cpu_count(logical=True),
                "cpu_physical_cores": psutil.cpu_count(logical=False),
                "ram_total_bytes": mem.total,
                "ram_available_bytes": mem.available,
                "ram_used_percent": mem.percent,
                "boot_time": boot_time_dt,
                "uptime_seconds": uptime_seconds,
                "current_user": current_user
            }

            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="SUCCESS",
                data=system_data,
                item_count=len(system_data),
                metadata={"platform": platform.system()}
            )
        except Exception as e:
            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="FAILED",
                error=f"Error collecting system info: {str(e)}",
                data={}
            )
