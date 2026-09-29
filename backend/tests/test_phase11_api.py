import asyncio
import sys
from pathlib import Path
import httpx

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.main import app, lifespan

async def run_api_tests():
    print("Testing Phase 11: FastAPI REST Endpoints & Complete Investigation Lifecycle...")
    async with lifespan(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Test Health
            h_res = await client.get("/api/health")
            assert h_res.status_code == 200
            print("[PASS] GET /api/health -> 200 OK")

            # 2. Test Machines Endpoint
            m_res = await client.get("/api/machines")
            assert m_res.status_code == 200
            machines = m_res.json()
            assert len(machines) >= 1
            machine_id = machines[0]["id"]
            print(f"[PASS] GET /api/machines -> Found {len(machines)} machine(s), target: {machine_id}")

            # 3. Create Investigation
            create_payload = {
                "intent": "suspicious_network_activity",
                "machine_id": machine_id
            }
            c_res = await client.post("/api/investigations", json=create_payload)
            assert c_res.status_code == 200
            inv_data = c_res.json()
            inv_id = inv_data["id"]
            print(f"[PASS] POST /api/investigations -> Created {inv_id} for intent: {inv_data['intent']}")

            # 4. Preview Plan & Evidence Requirement Graph
            p_res = await client.post(f"/api/investigations/{inv_id}/preview")
            assert p_res.status_code == 200
            preview_data = p_res.json()
            assert "evidence_graph" in preview_data
            assert "workflow" in preview_data
            assert len(preview_data["workflow"]["steps"]) >= 4
            print(f"[PASS] POST /api/investigations/{inv_id}/preview -> Graph nodes: {preview_data['evidence_graph']['total_nodes']}, Planned steps: {preview_data['workflow']['total_steps']}")

            # 5. Execute Investigation
            print("       Executing investigation workflow...")
            e_res = await client.post(f"/api/investigations/{inv_id}/execute")
            assert e_res.status_code == 200
            exec_data = e_res.json()
            assert exec_data["status"] == "COMPLETED"
            assert exec_data["rounds_executed"] >= 1
            print(f"[PASS] POST /api/investigations/{inv_id}/execute -> Status: {exec_data['status']}, Rounds: {exec_data['rounds_executed']}, Artifacts: {exec_data['artifacts_collected']}")

            # 6. Fetch Evidence Artifacts
            ev_res = await client.get(f"/api/investigations/{inv_id}/evidence")
            assert ev_res.status_code == 200
            artifacts = ev_res.json()
            assert len(artifacts) >= 4
            print(f"[PASS] GET /api/investigations/{inv_id}/evidence -> Retrieved {len(artifacts)} evidence artifacts")

            # 7. Fetch Immutable Provenance Ledger
            prov_res = await client.get(f"/api/investigations/{inv_id}/provenance")
            assert prov_res.status_code == 200
            prov_records = prov_res.json()
            assert len(prov_records) == len(artifacts)
            print(f"[PASS] GET /api/investigations/{inv_id}/provenance -> Retrieved {len(prov_records)} provenance records")

            # 8. Verify Cryptographic Integrity
            v_res = await client.post(f"/api/investigations/{inv_id}/verify")
            assert v_res.status_code == 200
            verify_data = v_res.json()
            assert verify_data["all_valid"] is True
            assert verify_data["valid_count"] == len(artifacts)
            print(f"[PASS] POST /api/investigations/{inv_id}/verify -> {verify_data['valid_count']}/{verify_data['total_artifacts']} Artifacts SHA-256 VALID")

            # 9. Fetch Chronological Timeline
            tl_res = await client.get(f"/api/investigations/{inv_id}/timeline")
            assert tl_res.status_code == 200
            timeline = tl_res.json()
            assert len(timeline) >= 4
            print(f"[PASS] GET /api/investigations/{inv_id}/timeline -> Retrieved {len(timeline)} chronological events")

            # 10. Generate Report
            rep_res = await client.get(f"/api/investigations/{inv_id}/report")
            assert rep_res.status_code == 200
            report_data = rep_res.json()
            assert "JOCKY FORENSIC INVESTIGATION REPORT" in report_data["markdown"]
            assert "<html" in report_data["html"].lower()
            print(f"[PASS] GET /api/investigations/{inv_id}/report -> Markdown ({len(report_data['markdown'])} chars) & HTML generated")


import pytest

@pytest.mark.asyncio
async def test_api_investigation_lifecycle():
    await run_api_tests()


if __name__ == "__main__":
    asyncio.run(run_api_tests())
    print("\n>>> ALL PHASE 11 FASTAPI REST ENDPOINT TESTS PASSED SUCCESSFULLY! <<<\n")
