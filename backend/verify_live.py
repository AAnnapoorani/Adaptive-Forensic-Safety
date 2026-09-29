import urllib.request
import json

def test_live_mode():
    base_url = "http://127.0.0.1:8000/api"

    print("[LIVE MODE TEST] Creating investigation...")
    create_body = json.dumps({
        "intent": "suspicious_network_activity",
        "script": "# Safe live collection test\nINVESTIGATE suspicious_network_activity"
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/investigations",
        data=create_body,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        inv = json.loads(resp.read().decode())
        inv_id = inv["id"]
        print("  -> Investigation ID:", inv_id)

    print(f"[LIVE MODE TEST] Executing investigation {inv_id} with demo=False...")
    exec_req = urllib.request.Request(
        f"{base_url}/investigations/{inv_id}/execute?demo=false",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(exec_req) as resp:
        exec_res = json.loads(resp.read().decode())
        print("  -> Live execution status:", exec_res["status"])
        print("  -> Artifacts collected:", exec_res["artifacts_collected"])
        print("  -> Rounds executed:", exec_res["rounds_executed"])
        print("  -> Integrity verified:", exec_res["integrity_verified"])
        assert exec_res["status"] in ("COMPLETED", "CONVERGED")
        assert exec_res["artifacts_collected"] >= 1
        assert exec_res["integrity_verified"] is True

    # Verify SHA-256 integrity of live collected evidence
    prov_req = urllib.request.Request(
        f"{base_url}/investigations/{inv_id}/verify",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(prov_req) as resp:
        prov = json.loads(resp.read().decode())
        print("  -> Provenance verification:", prov["all_valid"])
        assert prov["all_valid"] is True

    print("\n>>> LIVE MODE SAFE READ-ONLY EXECUTION PASSED 100%! <<<\n")

if __name__ == "__main__":
    test_live_mode()
