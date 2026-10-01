"""
JOCKY Extended REST API Endpoints — 100% Live Implementation

  POST /api/jocky/mutate            — Polymorphic script generation (unique SHA-256 per output)
  POST /api/jocky/encrypt           — Evidence payload encryption (PBKDF2 + XOR + AES-128-CBC)
  POST /api/jocky/decrypt           — Evidence payload decryption
  GET  /api/jocky/drivers           — LIVE: kernel driver enumeration & BYOVD detection (Win32 ctypes)
  GET  /api/jocky/memory            — LIVE: in-memory injection detection (VirtualQueryEx direct call)
  GET  /api/jocky/inmemory          — LIVE: all 5 in-memory execution probes (ntdll unhook, hollowing, thread ctx...)
  GET  /api/jocky/inmemory/ntdll    — LIVE: ntdll.dll hook detection & unhooking report
  GET  /api/jocky/inmemory/vquery   — LIVE: direct VirtualQueryEx syscall probe
  GET  /api/jocky/inmemory/hollow   — LIVE: process hollowing MZ-header detection
  GET  /api/jocky/inmemory/thread   — LIVE: thread context (RIP/RSP) probe
  GET  /api/jocky/inmemory/rdll     — LIVE: reflective DLL injection indicator scan
  GET  /api/jocky/cdn/status        — LIVE: current CDN tunnel status & public URL
  POST /api/jocky/cdn/direct        — Activate DIRECT mode
  POST /api/jocky/cdn/cloudflare    — LIVE: spawn real cloudflared tunnel subprocess
  POST /api/jocky/cdn/domainfront   — LIVE: configure TLS domain fronting
  POST /api/jocky/cdn/ngrok         — LIVE: spawn real ngrok tunnel subprocess
  POST /api/jocky/cdn/stop          — Stop active tunnel
  GET  /api/jocky/cdn/test          — Test public URL reachability
  GET  /api/jocky/routing           — Legacy: CDN routing config (compat)
  POST /api/jocky/routing           — Legacy: update routing mode (compat)
  GET  /api/jocky/remote-machines   — List registered remote machines
  POST /api/jocky/remote-machines   — Register remote machine
  POST /api/jocky/remote-machines/ping    — SSH connectivity ping
  POST /api/jocky/remote-machines/collect — Parallel multi-machine collection
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from pydantic import BaseModel
from typing import Any

router = APIRouter(prefix="/jocky", tags=["JOCKY Extended — Evasion & Multi-Machine"])


# ─── Request/Response Schemas ────────────────────────────────────────────────

class MutateRequest(BaseModel):
    script: str
    iterations: int = 3

class EncryptRequest(BaseModel):
    payload: Any
    investigation_id: str

class DecryptRequest(BaseModel):
    blob_hex: str          # hex-encoded encrypted blob
    investigation_id: str

class RemoteMachineRegisterRequest(BaseModel):
    machine_id: str
    hostname: str
    ip_address: str
    os_type: str = "windows"
    port: int = 22
    username: str = ""
    auth_method: str = "password"
    ssh_key_path: str | None = None
    tags: list[str] = []

class MultiMachineExecuteRequest(BaseModel):
    machine_ids: list[str]
    operations: list[str]
    credentials: dict[str, str] = {}

class CDNRoutingRequest(BaseModel):
    routing_mode: str = "DIRECT"      # DIRECT | CLOUDFLARE | DOMAIN_FRONT | NGROK
    cdn_domain: str | None = None
    real_host: str | None = None
    proxy_url: str | None = None
    api_key: str | None = None


# ─── In-memory registry for remote machines (demo store) ─────────────────────
_REMOTE_MACHINES: dict[str, dict] = {}
_CDN_CONFIG: dict = {"routing_mode": "DIRECT", "cdn_domain": None, "real_host": None}


# ─── Polymorphic Engine Endpoints ────────────────────────────────────────────

@router.post("/mutate", summary="Generate polymorphic JOCKY script variants (unique SHA-256 per output)")
def mutate_script(req: MutateRequest):
    """
    Applies the Polymorphic Engine to produce N structurally-equivalent but
    lexically unique JOCKY script variants. Every output has a different SHA-256
    hash, neutralizing file-reputation AV databases.
    """
    try:
        from app.jocky.polymorphic import PolymorphicEngine
        if not req.script or not req.script.strip():
            raise HTTPException(status_code=400, detail="Script cannot be empty")
        if req.iterations < 1 or req.iterations > 20:
            raise HTTPException(status_code=400, detail="Iterations must be between 1 and 20")
        result = PolymorphicEngine.mutate(req.script, iterations=req.iterations)
        return {
            "status": "SUCCESS",
            "original_hash": result["original_hash"],
            "variant_count": result["iteration_count"],
            "all_hashes_unique": len(set(result["hashes"])) == len(result["hashes"]),
            "hashes": result["hashes"],
            "variants": result["variants"],
            "mutation_techniques": result["mutation_techniques"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-uniqueness", summary="Verify that a set of scripts all have unique SHA-256 hashes")
def verify_uniqueness(scripts: list[str]):
    """Verify polymorphic output hash uniqueness."""
    from app.jocky.polymorphic import PolymorphicEngine
    return PolymorphicEngine.verify_uniqueness(scripts)


# ─── Payload Encryption Endpoints ────────────────────────────────────────────

@router.post("/encrypt", summary="Encrypt evidence payload with XOR+AES-128-CBC (per-investigation key)")
def encrypt_payload(req: EncryptRequest):
    """
    Encrypts a JSON payload using a per-investigation derived key (PBKDF2 + XOR + AES-CBC).
    Returns a hex-encoded encrypted blob and the payload SHA-256 for integrity verification.
    """
    try:
        from app.jocky.polymorphic import PayloadEncryptor
        blob = PayloadEncryptor.encrypt(req.payload, req.investigation_id)
        payload_hash = PayloadEncryptor.compute_evidence_hash(req.payload)
        return {
            "status": "ENCRYPTED",
            "investigation_id": req.investigation_id,
            "blob_hex": blob.hex(),
            "blob_size_bytes": len(blob),
            "payload_sha256": payload_hash,
            "encryption_scheme": "XOR(PBKDF2-key) + AES-128-CBC",
            "key_derivation": "PBKDF2-HMAC-SHA256(investigation_id:salt, iterations=100000)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decrypt", summary="Decrypt an encrypted evidence blob")
def decrypt_payload(req: DecryptRequest):
    """Decrypt a hex-encoded encrypted evidence blob back to JSON."""
    try:
        from app.jocky.polymorphic import PayloadEncryptor
        blob = bytes.fromhex(req.blob_hex)
        data = PayloadEncryptor.decrypt(blob, req.investigation_id)
        return {
            "status": "DECRYPTED",
            "investigation_id": req.investigation_id,
            "payload": data,
            "integrity_hash": PayloadEncryptor.compute_evidence_hash(data)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


# ─── Driver & Memory Evasion Detection Endpoints ────────────────────────────

@router.get("/drivers", summary="Enumerate loaded kernel drivers & detect BYOVD vulnerable drivers")
def list_drivers():
    """
    Runs the DRIVERS.LIST collector — enumerates all loaded kernel-mode drivers
    using direct Win32 EnumDeviceDrivers API (ctypes, low EDR visibility) and
    cross-references against a curated BYOVD vulnerability database.
    """
    try:
        from app.collectors.drivers import DriversListCollector
        collector = DriversListCollector()
        result = collector.collect()
        return {
            "operation": "DRIVERS.LIST",
            "status": result.status,
            "item_count": result.item_count,
            "drivers": result.data,
            "metadata": result.metadata,
            "error": result.error
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/memory", summary="Detect in-memory injection: process hollowing, reflective DLL, shellcode")
def analyze_memory():
    """
    Runs the MEMORY.ANALYSIS collector — scans all process virtual address spaces
    via direct VirtualQueryEx (ctypes kernel32) to detect anomalous private
    executable memory regions indicating active code injection.
    """
    try:
        from app.collectors.drivers import MemoryAnalysisCollector
        collector = MemoryAnalysisCollector()
        result = collector.collect()
        return {
            "operation": "MEMORY.ANALYSIS",
            "status": result.status,
            "item_count": result.item_count,
            "suspicious_regions": result.data,
            "metadata": result.metadata,
            "error": result.error
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Live In-Memory Execution Probe Endpoints ────────────────────────────────

@router.get("/inmemory", summary="Run all 5 live in-memory execution probes")
def run_all_inmemory_probes():
    """
    Runs all 5 live in-memory execution probes via ctypes Win32:
    1. ntdll API hook detection (EDR unhooking reconnaissance)
    2. Direct VirtualQueryEx syscall probe
    3. Process hollowing MZ-header mismatch detection
    4. Thread context (RIP/RSP) capture probe
    5. Reflective DLL injection indicator scan
    All probes are STRICTLY READ-ONLY.
    """
    try:
        from app.jocky.ntdll_unhook import run_all_inmemory_probes as _run
        return _run()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inmemory/ntdll", summary="LIVE: ntdll.dll EDR hook detection & API unhooking report")
def probe_ntdll():
    """Detects EDR JMP hooks in in-memory ntdll.dll by diffing against fresh disk copy."""
    try:
        from app.jocky.ntdll_unhook import probe_ntdll_hooks
        return probe_ntdll_hooks()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inmemory/vquery", summary="LIVE: Direct VirtualQueryEx syscall probe on current process")
def probe_vquery():
    """Calls VirtualQueryEx directly via ctypes kernel32, bypassing hooked CRT APIs."""
    try:
        from app.jocky.ntdll_unhook import probe_direct_virtualquery
        return probe_direct_virtualquery()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inmemory/hollow", summary="LIVE: Detect process hollowing via PEB MZ-header mismatch")
def probe_hollow():
    """Scans running processes for invalid/missing MZ headers (hollowing indicator)."""
    try:
        from app.jocky.ntdll_unhook import probe_process_hollowing_readiness
        return probe_process_hollowing_readiness()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inmemory/thread", summary="LIVE: Thread context (RIP/RSP) probe — hijacking reconnaissance")
def probe_thread():
    """Opens thread handles and reads CONTEXT (RIP, RSP, RAX) — read-only hijack recon demo."""
    try:
        from app.jocky.ntdll_unhook import probe_thread_context
        return probe_thread_context()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inmemory/rdll", summary="LIVE: Reflective DLL injection — MZ header in private exec regions")
def probe_rdll():
    """Scans process VADs for MZ headers in private executable anonymous regions."""
    try:
        from app.jocky.ntdll_unhook import probe_reflective_dll_indicators
        return probe_reflective_dll_indicators()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Live CDN / Tunnel Endpoints ──────────────────────────────────────────────

class CloudflareRequest(BaseModel):
    local_url: str = "http://127.0.0.1:8000"

class DomainFrontRequest(BaseModel):
    cdn_domain: str = "ajax.microsoft.com"
    real_host: str = "127.0.0.1:8000"
    local_url: str = "http://127.0.0.1:8000"

class NgrokRequest(BaseModel):
    local_url: str = "http://127.0.0.1:8000"


@router.get("/cdn/status", summary="Get live CDN tunnel status & public URL")
def cdn_status():
    """Returns the live state of the active CDN tunnel including public URL."""
    try:
        from app.jocky.cdn_routing import get_routing_status
        return get_routing_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdn/direct", summary="Activate DIRECT mode (no tunnel)")
def cdn_direct():
    """Switch to direct HTTP — no tunnel or CDN routing."""
    try:
        from app.jocky.cdn_routing import activate_direct
        return activate_direct()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdn/cloudflare", summary="LIVE: Start real Cloudflare Tunnel (cloudflared subprocess)")
def cdn_cloudflare(req: CloudflareRequest):
    """
    Spawns a real cloudflared tunnel process and captures the live
    trycloudflare.com public URL. Requires cloudflared to be installed.
    """
    try:
        from app.jocky.cdn_routing import activate_cloudflare
        return activate_cloudflare(local_url=req.local_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdn/domainfront", summary="LIVE: Configure TLS domain fronting")
def cdn_domainfront(req: DomainFrontRequest):
    """
    Configures domain fronting: HTTPS SNI = cdn_domain, HTTP Host = real_host.
    Tests reachability and reports TLS handshake success.
    """
    try:
        from app.jocky.cdn_routing import activate_domain_front
        return activate_domain_front(
            cdn_domain=req.cdn_domain,
            real_host=req.real_host,
            local_url=req.local_url
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdn/ngrok", summary="LIVE: Start real ngrok tunnel subprocess")
def cdn_ngrok(req: NgrokRequest):
    """
    Spawns a real ngrok process and reads the live public URL from ngrok's
    local management API at 127.0.0.1:4040. Requires ngrok to be installed.
    """
    try:
        from app.jocky.cdn_routing import activate_ngrok
        return activate_ngrok(local_url=req.local_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdn/stop", summary="Stop the active CDN tunnel")
def cdn_stop():
    """Terminates the active cloudflared or ngrok tunnel process."""
    try:
        from app.jocky.cdn_routing import stop_tunnel
        return stop_tunnel()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cdn/test", summary="Test reachability of the active tunnel public URL")
def cdn_test():
    """Sends an HTTP GET to the active public URL and reports latency & HTTP status."""
    try:
        from app.jocky.cdn_routing import test_connectivity
        return test_connectivity()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Legacy CDN Routing Endpoints (backward-compat) ──────────────────────────

@router.get("/routing", summary="Legacy: Get CDN routing config")
def get_routing_config():
    """Returns the active CDN routing configuration (legacy endpoint)."""
    try:
        from app.jocky.cdn_routing import get_routing_status
        return get_routing_status()
    except Exception as e:
        return {"routing_mode": _CDN_CONFIG["routing_mode"], "note": "cdn_routing module unavailable"}


@router.post("/routing", summary="Legacy: Update CDN routing mode")
def update_routing_config(req: CDNRoutingRequest):
    """
    Legacy endpoint — updates CDN routing mode via the live cdn_routing module.
    Use /api/jocky/cdn/{mode} endpoints for full live tunnel management.
    """
    valid_modes = {"DIRECT", "CLOUDFLARE", "DOMAIN_FRONT", "NGROK"}
    mode = req.routing_mode.upper()
    if mode not in valid_modes:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode. Supported: {', '.join(sorted(valid_modes))}"
        )
    try:
        from app.jocky.cdn_routing import activate_direct, activate_cloudflare, activate_domain_front, activate_ngrok
        if mode == "DIRECT":
            return activate_direct()
        elif mode == "CLOUDFLARE":
            return activate_cloudflare()
        elif mode == "DOMAIN_FRONT":
            cdn = req.cdn_domain or "ajax.microsoft.com"
            host = req.real_host or "127.0.0.1:8000"
            return activate_domain_front(cdn_domain=cdn, real_host=host)
        elif mode == "NGROK":
            return activate_ngrok()
    except Exception as e:
        _CDN_CONFIG.update({"routing_mode": mode, "cdn_domain": req.cdn_domain, "real_host": req.real_host})
        return {"status": "ROUTING_UPDATED", "active_mode": mode, "note": str(e)}


# ─── Remote Machine Management Endpoints ─────────────────────────────────────

@router.get("/remote-machines", summary="List all registered remote forensic target machines")
def list_remote_machines(db: Session = Depends(get_db)):
    """Returns all registered remote endpoints (both SSH and live telemetry agent endpoints) available for multi-machine collection."""
    from app.models.machine import Machine
    from app.models.telemetry import MachineTelemetry
    db_machines = db.query(Machine).all()
    results = list(_REMOTE_MACHINES.values())

    for m in db_machines:
        latest = db.query(MachineTelemetry).filter(MachineTelemetry.machine_id == m.id).order_by(MachineTelemetry.timestamp.desc()).first()
        results.append({
            "machine_id": m.machine_id or m.id,
            "hostname": m.hostname,
            "ip_address": m.ip_address or "127.0.0.1",
            "os_type": m.os_type.lower() if m.os_type else "windows",
            "status": m.status,
            "agent_type": "JOCKY_LIVE_AGENT",
            "agent_version": m.agent_version,
            "last_seen": m.last_seen.isoformat() if m.last_seen else None,
            "tags": [m.os_name, m.architecture or "x86_64", "LIVE_TELEMETRY"],
            "telemetry": {
                "cpu_percent": latest.cpu_percent if latest else 0.0,
                "memory_percent": latest.memory_percent if latest else 0.0,
                "disk_percent": latest.disk_percent if latest else 0.0,
                "network_upload": latest.network_upload_speed if latest else 0.0,
                "network_download": latest.network_download_speed if latest else 0.0,
                "connections": latest.active_connections if latest else 0
            } if latest else None
        })

    return {
        "count": len(results),
        "machines": results
    }


@router.post("/remote-machines", summary="Register a new remote forensic target machine")
def register_remote_machine(req: RemoteMachineRegisterRequest):
    """Register a remote Windows or Linux endpoint for multi-machine forensic collection."""
    from app.services.remote_agent import RemoteMachine
    machine = RemoteMachine(
        machine_id=req.machine_id,
        hostname=req.hostname,
        ip_address=req.ip_address,
        os_type=req.os_type,
        port=req.port,
        username=req.username,
        auth_method=req.auth_method,
        ssh_key_path=req.ssh_key_path,
        tags=req.tags
    )
    _REMOTE_MACHINES[req.machine_id] = machine.to_dict()
    return {
        "status": "REGISTERED",
        "machine": machine.to_dict()
    }


@router.post("/remote-machines/ping", summary="Test SSH connectivity to all registered remote machines")
def ping_remote_machines():
    """
    Tests TCP and SSH connectivity to all registered remote machines concurrently.
    Returns latency and reachability status per machine.
    """
    from app.services.remote_agent import RemoteMachine, AgentPool
    if not _REMOTE_MACHINES:
        return {"message": "No remote machines registered", "results": []}
    machines = [RemoteMachine(**m) for m in _REMOTE_MACHINES.values()]
    pool = AgentPool(machines)
    return {"ping_results": pool.ping_all()}


@router.post("/remote-machines/collect", summary="Run forensic collectors on all registered remote machines in parallel")
def collect_remote_machines(req: MultiMachineExecuteRequest):
    """
    Executes a list of JOCKY forensic operations concurrently on multiple remote machines.
    Uses SSH-based RemoteAgent. Results aggregated per machine.
    """
    from app.services.remote_agent import RemoteMachine, AgentPool
    if not _REMOTE_MACHINES:
        raise HTTPException(status_code=404, detail="No remote machines registered")

    machines = [
        RemoteMachine(**m)
        for mid, m in _REMOTE_MACHINES.items()
        if not req.machine_ids or mid in req.machine_ids
    ]
    if not machines:
        raise HTTPException(status_code=404, detail="None of the specified machine IDs found")

    pool = AgentPool(machines)
    raw_results = pool.collect_all(req.operations, credentials=req.credentials)

    formatted = {}
    for mid, results in raw_results.items():
        formatted[mid] = [r.to_dict() for r in results]

    return {
        "status": "COLLECTION_COMPLETE",
        "machines_queried": len(machines),
        "operations": req.operations,
        "results": formatted
    }


# ─── In-Memory Activity & Security Analysis ───────────────────────────────────

@router.get("/security-analysis", summary="Run in-memory execution and anti-forensic security detection")
@router.get("/security/analysis", summary="Alias: Run in-memory execution and anti-forensic security detection")
def get_security_analysis():
    """
    Executes live non-invasive telemetry collectors and runs the JOCKY rule-based
    in-memory detection engine to detect hidden/fileless execution, hollowed processes,
    unusual parent-child relationships, unsigned services, and anomalous network connections.
    """
    from app.intelligence.in_memory_detection import run_live_detection
    return run_live_detection()


@router.post("/security-analysis", summary="Analyze supplied telemetry for in-memory indicators")
@router.post("/security/analysis", summary="Alias: Analyze supplied telemetry for in-memory indicators")
def post_security_analysis(evidence: dict[str, Any]):
    """
    Runs rule-based in-memory detection engine against investigator-supplied telemetry payload.
    """
    from app.intelligence.in_memory_detection import detect_in_memory_indicators
    return detect_in_memory_indicators(evidence)

@router.get("/etw-yara-audit", summary="Live ETW bypass and in-memory YARA rule scan")
def get_etw_yara_audit():
    """
    Conducts live audit of Event Tracing for Windows (ETW) EtwEventWrite integrity,
    AMSI buffer integrity, and scans active memory pages with YARA rules.
    """
    from app.services.ai_analyst import run_etw_yara_audit
    return run_etw_yara_audit()

