import asyncio
import sys
from pathlib import Path
import httpx

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.main import app, lifespan

async def run_demo_mode_test():
    print("Testing Phase 14: Deterministic Demo Mode & Adaptive Multi-Round Escalation...")
    async with lifespan(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create demo investigation
            c_res = await client.post("/api/investigations", json={
                "intent": "suspicious_network_activity"
            })
            assert c_res.status_code == 200
            inv = c_res.json()
            inv_id = inv["id"]
            print(f"[PASS] Created investigation: {inv_id} for intent: {inv['intent']}")

            # 2. Preview Plan
            p_res = await client.post(f"/api/investigations/{inv_id}/preview")
            assert p_res.status_code == 200
            preview = p_res.json()
            print(f"[PASS] Initial Plan: {preview['workflow']['total_steps']} steps planned for Round 1.")

            # 3. Execute with demo=True (Deterministic Synthetic Scenario)
            e_res = await client.post(f"/api/investigations/{inv_id}/execute?demo=true")
            assert e_res.status_code == 200
            result = e_res.json()
            print(f"[PASS] Execution completed with status: {result['status']}")
            print(f"       -> Rounds executed: {result['rounds_executed']}")
            print(f"       -> Artifacts collected: {result['artifacts_collected']}")
            print(f"       -> Timeline events count: {result['timeline_events_count']}")

            # Crucial verification: Adaptive escalation must have executed Round 2!
            assert result["rounds_executed"] >= 2, "Expected adaptive escalation to trigger Round 2"

            # 4. Check Rounds breakdown
            r_res = await client.get(f"/api/investigations/{inv_id}/rounds")
            assert r_res.status_code == 200
            rounds = r_res.json()
            assert len(rounds) >= 2
            print(f"[PASS] Multi-round execution confirmed:")
            for r in rounds:
                print(f"       -> Round {r['round_number']}: {r['trigger_reason']} (Artifacts: {r['artifacts_count']})")

            # 5. Check Matched Correlation Indicator
            corr_res = await client.get(f"/api/investigations/{inv_id}/correlations")
            assert corr_res.status_code == 200
            correlations = corr_res.json()
            rule_names = [c["rule_name"] for c in correlations]
            assert "POWERSHELL_NETWORK_ACTIVITY" in rule_names
            print(f"[PASS] Correlation rule matched: POWERSHELL_NETWORK_ACTIVITY")

            # 6. Check Evidence & Provenance & Synthetic Flag
            ev_res = await client.get(f"/api/investigations/{inv_id}/evidence")
            assert ev_res.status_code == 200
            artifacts = ev_res.json()
            assert all(a["is_synthetic"] is True for a in artifacts)
            assert any(a["operation"] == "PROCESS.PARENT_CHILD" for a in artifacts)
            assert any(a["operation"] == "COMMANDLINE.INFO" for a in artifacts)
            print(f"[PASS] Evidence correctly tagged as SYNTHETIC DEMO DATA with full SHA-256 integrity.")

            # 7. Check Integrity
            v_res = await client.post(f"/api/investigations/{inv_id}/verify")
            assert v_res.status_code == 200
            assert v_res.json()["all_valid"] is True
            print(f"[PASS] Cryptographic integrity: 100% Valid.")


import pytest

@pytest.mark.asyncio
async def test_demo_mode_escalation():
    await run_demo_mode_test()


if __name__ == "__main__":
    asyncio.run(run_demo_mode_test())
    print("\n>>> ALL PHASE 14 DETERMINISTIC DEMO & ADAPTIVE ESCALATION TESTS PASSED! <<<\n")
