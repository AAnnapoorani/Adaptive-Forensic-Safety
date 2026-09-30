"""
JOCKY Standalone Machine Agent

Runs locally on Windows or Linux to:
1. Maintain stable, persistent physical machine identity
2. Accurately report OS details (Windows vs Linux)
3. Continuously stream live hardware telemetry (CPU, RAM, Disk, Network)
4. Stream running process table snapshots
5. Detect and stream forensic security events

Usage:
    python jocky_agent.py [--server URL] [--interval SECONDS] [--once] [--reset-identity]
"""

import sys
import time
import argparse
import hashlib
import subprocess
import requests
from identity import get_or_create_identity
from collectors import collect_system_metrics, collect_processes, detect_forensic_events

AGENT_VERSION = "1.0.0"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="JOCKY Standalone Machine Agent")
    parser.add_argument("--server", default="http://localhost:8000", help="FastAPI backend URL (default: http://localhost:8000)")
    parser.add_argument("--interval", type=int, default=5, help="Telemetry interval in seconds (default: 5)")
    parser.add_argument("--once", action="store_true", help="Send single telemetry burst and exit")
    parser.add_argument("--reset-identity", action="store_true", help="Force regenerate physical machine identity")
    parser.add_argument("--mock-os", choices=["linux", "windows"], default=None, help="Simulate a specific OS (e.g. linux) to test multi-OS dashboard")
    parser.add_argument("--hostname", default=None, help="Override hostname for the simulated host")
    args = parser.parse_args()

    server_url = args.server.rstrip("/")
    interval = max(args.interval, 1)

    print("=" * 65)
    print(f" JOCKY FORENSIC AGENT v{AGENT_VERSION}")
    print("=" * 65)

    # 1. Retrieve or generate stable machine identity
    ident = get_or_create_identity(force_reset=args.reset_identity, mock_os=args.mock_os, mock_hostname=args.hostname)
    print(f"[+] Stable Machine ID:  {ident.machine_id}")
    print(f"[+] Physical Hostname:  {ident.hostname}")
    print(f"[+] Operating System:   {ident.os_type} ({ident.os_name}) - {ident.os_version}")
    print(f"[+] Architecture:       {ident.architecture}")
    print(f"[+] Primary MAC:        {ident.mac_address}")
    print(f"[+] Target Backend URL: {server_url}")

    # 2. Register machine with backend
    reg_payload = {
        "machine_id": ident.machine_id,
        "hostname": ident.hostname,
        "os_type": ident.os_type,
        "os_name": ident.os_name,
        "os_version": ident.os_version,
        "architecture": ident.architecture,
        "mac_address": ident.mac_address,
        "agent_version": AGENT_VERSION
    }

    registered = False
    backoff = 2
    while not registered:
        try:
            print(f"\n[*] Registering machine with backend at {server_url}/api/machines/register ...")
            resp = requests.post(f"{server_url}/api/machines/register", json=reg_payload, timeout=8)
            if resp.status_code in (200, 201):
                res_data = resp.json()
                print(f"[OK] Machine successfully registered! Status: {res_data.get('status', 'ONLINE')}")
                registered = True
            else:
                print(f"[-] Registration returned HTTP {resp.status_code}: {resp.text}")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
        except requests.exceptions.RequestException as e:
            print(f"[-] Cannot connect to backend: {e}. Retrying in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

        if args.once and not registered:
            sys.exit(1)

    # 3. Telemetry streaming loop
    print(f"\n[*] Starting live telemetry streaming every {interval} seconds (Press Ctrl+C to stop)...")
    tick = 0
    last_auto_trigger = 0.0

    try:
        while True:
            tick += 1
            start_t = time.time()

            # Collect system metrics
            metrics = collect_system_metrics()

            # Collect processes every 3 ticks (~15 seconds) or on first tick
            processes = None
            if tick == 1 or tick % 3 == 0:
                processes = collect_processes(limit=25)

            # Check forensic events every 2 ticks (~10 seconds)
            events = None
            if tick % 2 == 0:
                events = detect_forensic_events(ident.machine_id)

            packet = {
                "machine_id": ident.machine_id,
                "metrics": metrics,
                "processes": processes,
                "events": events
            }

            # 1. Transmit telemetry packet
            try:
                post_resp = requests.post(f"{server_url}/api/telemetry", json=packet, timeout=6)
                if post_resp.status_code in (200, 201):
                    proc_info = f", {len(processes)} procs" if processes else ""
                    evt_info = f", {len(events)} events" if events else ""
                    print(f"[{metrics['timestamp'][11:19]}] Telemetry sent | CPU: {metrics['cpu_percent']}% | RAM: {metrics['memory_percent']}% | Net: {metrics['network_upload_speed']/1024:.1f}KB/s ^ {metrics['network_download_speed']/1024:.1f}KB/s v{proc_info}{evt_info}")
                else:
                    print(f"[!] Telemetry rejected HTTP {post_resp.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[!] Telemetry transmission warning: {e}")

            # 2. Autonomous Incident Trigger (Enhancement 2)
            if events:
                for evt in events:
                    if evt.get("requires_autonomous_investigation"):
                        now_sec = time.time()
                        if now_sec - last_auto_trigger > 300: # 5 min cooldown
                            last_auto_trigger = now_sec
                            print(f"\n[!] THREAT DETECTED: {evt.get('description')}")
                            print("[*] Automatically dispatching autonomous investigation to lock Ed25519 hash chain...")
                            try:
                                inv_payload = {
                                    "intent": f"AUTONOMOUS TRIAGE: {evt.get('description')[:120]}",
                                    "machine_id": ident.machine_id,
                                    "auto_execute": True
                                }
                                inv_resp = requests.post(f"{server_url}/api/investigations", json=inv_payload, timeout=10)
                                if inv_resp.status_code in (200, 201):
                                    inv_data = inv_resp.json()
                                    print(f"[+] Autonomous Case Created & Executed! Case ID: {inv_data.get('id')} | Artifacts: {inv_data.get('artifacts_collected')}\n")
                            except Exception as ex:
                                print(f"[!] Autonomous trigger warning: {ex}")

            # 3. Check for remote triage commands dispatched by investigator (Enhancement 3)
            try:
                cmd_resp = requests.get(f"{server_url}/api/machines/{ident.machine_id}/commands/pending", timeout=3)
                if cmd_resp.status_code == 200:
                    cmd_data = cmd_resp.json().get("command")
                    if cmd_data:
                        cmd_id = cmd_data["id"]
                        raw_cmd = cmd_data["command"]
                        print(f"\n[+] Executing remote triage command [{cmd_id}]: {raw_cmd}")
                        try:
                            # Safe execution with timeout
                            res = subprocess.run(raw_cmd, shell=True, capture_output=True, text=True, timeout=12)
                            out = res.stdout or ""
                            err = res.stderr or ""
                            exit_code = res.returncode
                        except subprocess.TimeoutExpired:
                            out = ""
                            err = "Command timed out after 12 seconds."
                            exit_code = 124
                        except Exception as ex:
                            out = ""
                            err = str(ex)
                            exit_code = 1

                        signed_hash = hashlib.sha256((out + err).encode("utf-8", errors="ignore")).hexdigest()
                        requests.post(
                            f"{server_url}/api/machines/{ident.machine_id}/commands/{cmd_id}/result",
                            json={"exit_code": exit_code, "output": out, "error": err, "signed_hash": signed_hash},
                            timeout=5
                        )
                        print(f"[+] Triage command completed (exit {exit_code}). Output sealed with SHA-256: {signed_hash[:16]}...\n")
            except Exception:
                pass

            if args.once:
                print("[*] Single run completed. Exiting.")
                break

            elapsed = time.time() - start_t
            sleep_time = max(interval - elapsed, 0.5)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n[*] Agent stopped by user. Machine will be marked OFFLINE after heartbeat timeout.")


if __name__ == "__main__":
    main()
