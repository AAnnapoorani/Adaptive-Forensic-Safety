import urllib.request
import json

def test_api():
    base_url = "http://127.0.0.1:8000/api"
    
    # 1. Health check
    print("[1] Testing Health Check...")
    with urllib.request.urlopen(f"{base_url}/health") as resp:
        data = json.loads(resp.read().decode())
        print("  -> Status:", resp.status, data["status"])
        assert data["status"] == "healthy"

    # 2. Preview Plan
    print("\n[2] Testing JOCKY DSL Preview Plan...")
    req_body = json.dumps({
        "script": "# Investigate suspicious outbound traffic\nINVESTIGATE suspicious_network_activity"
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/investigations/preview", 
        data=req_body, 
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        preview = json.loads(resp.read().decode())
        print("  -> Parsed intent:", preview["intent"])
        print("  -> Initial operations:", preview["initial_operations"])
        print("  -> DAG node count:", len(preview["evidence_graph"]["nodes"]))
        print("  -> Workflow steps:", len(preview["workflow"]["steps"]))
        assert preview["intent"] == "suspicious_network_activity"
        assert len(preview["initial_operations"]) == 4

    # 3. Create Investigation
    print("\n[3] Creating Investigation...")
    create_body = json.dumps({
        "intent": "suspicious_network_activity",
        "script": "# Outbound beaconing investigation\nINVESTIGATE suspicious_network_activity"
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/investigations",
        data=create_body,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        inv = json.loads(resp.read().decode())
        inv_id = inv["id"]
        print("  -> Created Investigation ID:", inv_id)
        print("  -> Status:", inv["status"])

    # 4. Execute Investigation in Demo Mode
    print(f"\n[4] Executing Adaptive Multi-Round Investigation {inv_id} in DEMO MODE...")
    exec_req = urllib.request.Request(
        f"{base_url}/investigations/{inv_id}/execute?demo=true",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(exec_req) as resp:
        exec_res = json.loads(resp.read().decode())
        print("  -> Execution completed status:", exec_res["status"])
        print("  -> Summary:", exec_res["summary"])
        print("  -> Rounds executed:", exec_res["rounds_executed"])
        print("  -> Total artifacts:", exec_res["artifacts_collected"])
        print("  -> Timeline events count:", exec_res["timeline_events_count"])
        print("  -> Integrity verified:", exec_res["integrity_verified"])
        assert exec_res["status"] in ("COMPLETED", "CONVERGED")
        assert exec_res["rounds_executed"] >= 2
        assert exec_res["artifacts_collected"] >= 4
        assert exec_res["integrity_verified"] is True

    # 5. Check Details & Rounds
    print(f"\n[5] Fetching Full Investigation Details & Rounds...")
    with urllib.request.urlopen(f"{base_url}/investigations/{inv_id}") as resp:
        details = json.loads(resp.read().decode())
        print(f"  -> Investigation Metrics: {details['metrics']}")
        assert details["status"] in ("COMPLETED", "CONVERGED")
        assert details["metrics"]["escalation_triggered"] is True

    with urllib.request.urlopen(f"{base_url}/investigations/{inv_id}/rounds") as resp:
        rounds = json.loads(resp.read().decode())
        print(f"  -> Total rounds returned: {len(rounds)}")
        for r in rounds:
            print(f"     Round {r['round_number']}: status={r['status']}, steps={r['steps_count']}, artifacts={r['artifacts_count']}, correlations={r['correlation_matches_count']}")
        assert len(rounds) >= 2

    # 6. Verify Cryptographic Provenance
    print(f"\n[6] Verifying Cryptographic Provenance Ledger...")
    prov_req = urllib.request.Request(
        f"{base_url}/investigations/{inv_id}/verify",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(prov_req) as resp:
        prov = json.loads(resp.read().decode())
        print("  -> Total artifacts verified:", prov["total_artifacts"])
        print("  -> Valid count:", prov["valid_count"])
        print("  -> All valid:", prov["all_valid"])
        assert prov["all_valid"] is True
        assert prov["valid_count"] == prov["total_artifacts"]

    # 7. Check Timeline
    print(f"\n[7] Checking Chronological Timeline...")
    with urllib.request.urlopen(f"{base_url}/investigations/{inv_id}/timeline") as resp:
        timeline = json.loads(resp.read().decode())
        print(f"  -> Total timeline events: {len(timeline)}")
        for ev in timeline[:5]:
            print(f"     [{ev['timestamp']}] [{ev['source']}] {ev['description']}")
        assert len(timeline) > 0

    # 8. Check Reports (Markdown and HTML)
    print(f"\n[8] Generating Forensic Report (JSON, Markdown, HTML)...")
    with urllib.request.urlopen(f"{base_url}/investigations/{inv_id}/report") as resp:
        report = json.loads(resp.read().decode())
        print("  -> Report investigation_id:", report["investigation_id"])
        print("  -> Report intent:", report["json"]["intent"])
        print("  -> Markdown length:", len(report["markdown"]))
        print("  -> HTML length:", len(report["html"]))
        assert "# JOCKY FORENSIC INVESTIGATION REPORT" in report["markdown"]
        assert "<!DOCTYPE html>" in report["html"]

    with urllib.request.urlopen(f"{base_url}/investigations/{inv_id}/report/html") as resp:
        html_content = resp.read().decode()
        assert "<!DOCTYPE html>" in html_content
        assert "JOCKY Forensic Investigation Report" in html_content
        print("  -> HTML report endpoint directly returns valid HTML page.")

    # 9. Test Invalid Syntax error handling
    print(f"\n[9] Testing Invalid JOCKY DSL Syntax Handling...")
    bad_req = urllib.request.Request(
        f"{base_url}/investigations/preview",
        data=json.dumps({"script": "INVESTIGATE"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(bad_req)
        assert False, "Should have raised HTTP 400"
    except urllib.error.HTTPError as e:
        err_msg = json.loads(e.read().decode())
        print("  -> Correctly rejected with HTTP 400:", err_msg["detail"])
        assert "Expected an investigation intent after INVESTIGATE" in err_msg["detail"]

    # 10. Test Unknown Intent Error Handling
    print(f"\n[10] Testing Unknown Intent Handling...")
    unknown_req = urllib.request.Request(
        f"{base_url}/investigations/preview",
        data=json.dumps({"script": "INVESTIGATE alien_invasion"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(unknown_req)
        assert False, "Should have raised HTTP 400"
    except urllib.error.HTTPError as e:
        err_msg = json.loads(e.read().decode())
        print("  -> Correctly rejected with HTTP 400:", err_msg["detail"])
        assert "Unknown investigation intent 'alien_invasion'" in err_msg["detail"]

    print("\n=======================================================")
    print("ALL 10 API & PIPELINE VERIFICATION CHECKS PASSED 100%!")
    print("=======================================================")

if __name__ == "__main__":
    test_api()
