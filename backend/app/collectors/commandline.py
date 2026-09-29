import psutil
from app.collectors.base import BaseCollector, CollectorResult

class ProcessParentChildCollector(BaseCollector):
    name: str = "Process Parent-Child Hierarchy Collector"
    operation: str = "PROCESS.PARENT_CHILD"
    description: str = "Constructs parent-child execution lineages and lineage trees for all active processes."

    def collect(self, params: dict | None = None) -> CollectorResult:
        proc_lookup: dict[int, dict] = {}
        relationships = []

        # 1. Collect all processes with ppid
        for proc in psutil.process_iter(['pid', 'ppid', 'name']):
            try:
                info = proc.as_dict(attrs=['pid', 'ppid', 'name'])
                proc_lookup[info['pid']] = {
                    "pid": info['pid'],
                    "ppid": info.get('ppid'),
                    "name": info.get('name') or "unknown"
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 2. Build parent-child relationships
        for pid, pdata in proc_lookup.items():
            ppid = pdata.get("ppid")
            parent_name = "unknown"
            if ppid and ppid in proc_lookup:
                parent_name = proc_lookup[ppid]["name"]
            
            relationships.append({
                "child_pid": pid,
                "child_name": pdata["name"],
                "parent_pid": ppid,
                "parent_name": parent_name
            })

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS",
            data=relationships,
            item_count=len(relationships),
            metadata={"total_relationships": len(relationships)}
        )


class CommandLineInfoCollector(BaseCollector):
    name: str = "Process CommandLine Arguments Collector"
    operation: str = "COMMANDLINE.INFO"
    description: str = "Collects full executable execution arguments and flags for active processes."

    def collect(self, params: dict | None = None) -> CollectorResult:
        cmdlines = []
        errors = 0

        target_pid = params.get("pid") if params else None

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.pid
                if target_pid and pid != target_pid:
                    continue

                name = proc.name()
                try:
                    raw_cmd = proc.cmdline()
                    joined = " ".join(raw_cmd) if raw_cmd else None
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    joined = None

                if joined:
                    cmdlines.append({
                        "pid": pid,
                        "name": name,
                        "command_line": joined,
                        "arg_count": len(raw_cmd) if raw_cmd else 0
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                errors += 1
                continue

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS",
            data=cmdlines,
            item_count=len(cmdlines),
            metadata={
                "commandlines_captured": len(cmdlines),
                "inaccessible_processes": errors
            }
        )
