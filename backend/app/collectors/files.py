import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from app.core.config import settings
from app.collectors.base import BaseCollector, CollectorResult

class FilesRecentCollector(BaseCollector):
    name: str = "Recent Files Collector"
    operation: str = "FILES.RECENT"
    description: str = "Safely inspects files in the designated monitored forensic directory."

    def collect(self, params: dict | None = None) -> CollectorResult:
        scan_dir = Path(params.get("directory")) if (params and params.get("directory")) else settings.SAFE_SCAN_DIR
        
        # Ensure scan directory exists and has baseline forensic demonstration files if empty
        scan_dir.mkdir(parents=True, exist_ok=True)
        sample_file = scan_dir / "network_tool_download.tmp"
        if not any(scan_dir.iterdir()):
            sample_file.write_text("powershell -ExecutionPolicy Bypass -Command ... [DEMO ARTIFACT]")

        file_list = []
        errors = 0

        limit = (params.get("limit") if params else None) or 100

        try:
            for root, dirs, files in os.walk(scan_dir):
                # Avoid heavy or system-locked cache folders
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "AppData", "venv", ".git")]
                for f in files:
                    item = Path(root) / f
                    try:
                        stat = item.stat()
                        ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
                        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                        
                        file_list.append({
                            "path": str(item.resolve()),
                            "filename": item.name,
                            "extension": item.suffix.lower(),
                            "size_bytes": stat.st_size,
                            "created_time": ctime,
                            "modified_time": mtime,
                            "is_executable": item.suffix.lower() in (".exe", ".bat", ".ps1", ".vbs", ".cmd", ".sh", ".tmp")
                        })
                        if len(file_list) >= limit:
                            break
                    except Exception:
                        errors += 1
                        continue
                if len(file_list) >= limit:
                    break
        except Exception as e:
            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="FAILED",
                error=f"Error accessing monitored directory: {str(e)}",
                data=[]
            )

        # Sort by modification time descending
        file_list.sort(key=lambda x: x.get("modified_time", ""), reverse=True)

        return CollectorResult(
            collector_name=self.name,
            operation=self.operation,
            status="SUCCESS",
            data=file_list,
            item_count=len(file_list),
            metadata={
                "monitored_directory": str(scan_dir),
                "total_files": len(file_list),
                "skipped_files": errors
            }
        )


class FileHashCollector(BaseCollector):
    name: str = "File Cryptographic Hash Collector"
    operation: str = "FILE.HASH"
    description: str = "Calculates SHA-256 cryptographic hash of a specified file without executing it."

    def collect(self, params: dict | None = None) -> CollectorResult:
        if not params or not params.get("path"):
            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="FAILED",
                error="Missing required 'path' parameter for FILE.HASH"
            )

        raw_path = params.get("path")
        target_path = Path(raw_path)

        # If relative, resolve against SAFE_SCAN_DIR or BASE_DIR
        if not target_path.is_absolute():
            potential = settings.SAFE_SCAN_DIR / target_path
            if potential.exists():
                target_path = potential
            else:
                target_path = settings.BASE_DIR / target_path

        if not target_path.exists() or not target_path.is_file():
            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="FAILED",
                error=f"File not found: {raw_path}",
                data={"path": str(raw_path), "exists": False}
            )

        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            file_size = 0

            with open(target_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    file_size += len(chunk)

            stat = target_path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

            hash_data = {
                "path": str(target_path.resolve()),
                "filename": target_path.name,
                "file_size_bytes": file_size,
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest(),
                "modified_time": mtime,
                "exists": True
            }

            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="SUCCESS",
                data=hash_data,
                item_count=1,
                metadata={"algorithm": "SHA-256"}
            )
        except Exception as e:
            return CollectorResult(
                collector_name=self.name,
                operation=self.operation,
                status="FAILED",
                error=f"Hashing failed: {str(e)}",
                data={"path": str(target_path), "exists": True}
            )
