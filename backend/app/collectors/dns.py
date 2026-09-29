import platform
import subprocess
import re
from app.collectors.base import BaseCollector, CollectorResult

class DnsInfoCollector(BaseCollector):
    name: str = "DNS Configuration and Cache Collector"
    operation: str = "DNS.INFO"
    description: str = "Safely inspects local DNS server resolvers and local DNS cache entries."

    def collect(self, params: dict | None = None) -> CollectorResult:
        dns_records = []
        dns_servers = []
        system = platform.system()

        if system == "Windows":
            # 1. Fetch configured DNS servers safely
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    for line in res.stdout.strip().splitlines():
                        clean = line.strip()
                        if clean and clean not in dns_servers:
                            dns_servers.append(clean)
            except Exception:
                pass

            # 2. Fetch local DNS cache entries (capped at 50)
            try:
                cmd = ["ipconfig", "/displaydns"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    current_entry: dict = {}
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if "Record Name" in line:
                            if current_entry and current_entry.get("record_name"):
                                dns_records.append(current_entry)
                                if len(dns_records) >= 50:
                                    break
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                current_entry = {"record_name": parts[1].strip(), "type": "A", "data": ""}
                        elif "Record Type" in line:
                            parts = line.split(":", 1)
                            if len(parts) == 2 and current_entry:
                                current_entry["type"] = parts[1].strip()
                        elif ("A (Host) Record" in line or "Data" in line or "PTR Record" in line or "CNAME" in line):
                            parts = line.split(":", 1)
                            if len(parts) == 2 and current_entry:
                                current_entry["data"] = parts[1].strip()

                    if current_entry and current_entry.get("record_name") and len(dns_records) < 50:
                        dns_records.append(current_entry)
            except Exception as e:
                # Safe failure, don't crash
                pass

        elif system == "Linux":
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) > 1:
                                dns_servers.append(parts[1])
            except Exception:
                pass

        status = "SUCCESS" if (dns_servers or dns_records) else "NOT_AVAILABLE"

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status=status,
            data={
                "dns_servers": dns_servers,
                "cached_records": dns_records,
                "platform": system
            },
            item_count=len(dns_records) + len(dns_servers),
            metadata={
                "server_count": len(dns_servers),
                "cache_records_count": len(dns_records)
            }
        )
