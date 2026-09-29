import ipaddress
import psutil
from app.collectors.base import BaseCollector, CollectorResult

def is_external_ip(ip_str: str) -> bool:
    """Check if an IP address is a public/external routable address."""
    if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

class NetworkConnectionsCollector(BaseCollector):
    name: str = "Network Connections Collector"
    operation: str = "NETWORK.CONNECTIONS"
    description: str = "Collects active local and remote TCP/UDP sockets, states, and bound process IDs."

    def collect(self, params: dict | None = None) -> CollectorResult:
        connections = []
        errors = 0

        # Cache process names by PID to avoid repeated lookups
        proc_names: dict[int, str] = {}

        try:
            net_conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            # Fallback to per-process connections if global connections call fails due to elevation
            net_conns = []
            for p in psutil.process_iter(['pid']):
                try:
                    for conn in p.net_connections(kind='inet'):
                        net_conns.append(conn)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

        for conn in net_conns:
            try:
                laddr_ip = conn.laddr.ip if conn.laddr else None
                laddr_port = conn.laddr.port if conn.laddr else None
                raddr_ip = conn.raddr.ip if conn.raddr else None
                raddr_port = conn.raddr.port if conn.raddr else None

                pid = conn.pid
                pname = None
                if pid:
                    if pid in proc_names:
                        pname = proc_names[pid]
                    else:
                        try:
                            proc = psutil.Process(pid)
                            pname = proc.name()
                            proc_names[pid] = pname
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pname = "unknown"

                is_external = is_external_ip(raddr_ip) if raddr_ip else False

                connections.append({
                    "family": str(conn.family.name if hasattr(conn.family, 'name') else conn.family),
                    "type": str(conn.type.name if hasattr(conn.type, 'name') else conn.type),
                    "local_address": laddr_ip,
                    "local_port": laddr_port,
                    "remote_address": raddr_ip,
                    "remote_port": raddr_port,
                    "status": conn.status,
                    "pid": pid,
                    "process_name": pname,
                    "is_external": is_external
                })
            except Exception:
                errors += 1
                continue

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS",
            data=connections,
            item_count=len(connections),
            metadata={
                "total_connections": len(connections),
                "external_connections_count": sum(1 for c in connections if c["is_external"]),
                "parse_errors": errors
            }
        )
