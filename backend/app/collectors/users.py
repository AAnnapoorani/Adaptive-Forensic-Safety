import platform
import subprocess
from datetime import datetime, timezone
import psutil
from app.collectors.base import BaseCollector, CollectorResult

class UsersListCollector(BaseCollector):
    name: str = "Users List Collector"
    operation: str = "USERS.LIST"
    description: str = "Collects logged in sessions and local system user accounts."

    def collect(self, params: dict | None = None) -> CollectorResult:
        active_sessions = []
        local_accounts = []

        # 1. Active sessions via psutil
        try:
            for u in psutil.users():
                started_iso = datetime.fromtimestamp(u.started, tz=timezone.utc).isoformat() if u.started else None
                active_sessions.append({
                    "name": u.name,
                    "terminal": u.terminal or "console",
                    "host": u.host or "localhost",
                    "started": started_iso,
                    "pid": getattr(u, 'pid', None)
                })
        except Exception:
            pass

        # 2. Local accounts enumeration
        system = platform.system()
        if system == "Windows":
            try:
                res = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    lines = res.stdout.splitlines()
                    # Skip header until the dashed line
                    capture = False
                    for line in lines:
                        if "----" in line:
                            capture = True
                            continue
                        if capture:
                            if "The command completed successfully" in line:
                                break
                            for acc in line.split():
                                clean = acc.strip()
                                if clean:
                                    local_accounts.append({"username": clean, "type": "LOCAL"})
            except Exception:
                pass
        elif system == "Linux":
            try:
                with open("/etc/passwd", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 6:
                            local_accounts.append({
                                "username": parts[0],
                                "uid": parts[2],
                                "gid": parts[3],
                                "home": parts[5],
                                "shell": parts[6] if len(parts) > 6 else ""
                            })
            except Exception:
                pass

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS",
            data={
                "active_sessions": active_sessions,
                "local_accounts": local_accounts
            },
            item_count=len(active_sessions) + len(local_accounts),
            metadata={
                "active_session_count": len(active_sessions),
                "local_account_count": len(local_accounts)
            }
        )
