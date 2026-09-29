import asyncio
import sys
from pathlib import Path
# pyrefly: ignore [missing-import]
import httpx

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.main import app, lifespan
from app.core.database import SessionLocal
from app.models.machine import Machine

async def run_tests():
    async with lifespan(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Test Root
            response = await client.get("/")
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            assert "JOCKY" in data["title"]
            assert data["health"] == "/api/health"
            print("[PASS] Root endpoint verified.")

            # 2. Test Health Endpoint
            health_resp = await client.get("/api/health")
            assert health_resp.status_code == 200, f"Expected 200, got {health_resp.status_code}"
            health_data = health_resp.json()
            assert health_data["status"] == "healthy"
            assert health_data["database"] == "connected"
            assert health_data["platform"]["system"] in ["Windows", "Linux", "Darwin"]
            print("[PASS] Health check verified:", health_data)

            # 3. Test Machine Registration in Database
            db = SessionLocal()
            try:
                machines = db.query(Machine).all()
                assert len(machines) >= 1, "Expected at least 1 registered machine"
                m = machines[0]
                print(f"[PASS] Auto-registered machine: {m.id} (OS: {m.os_name})")
            finally:
                db.close()

def test_phase1_foundation():
    asyncio.run(run_tests())

if __name__ == "__main__":
    asyncio.run(run_tests())
    print("\n>>> ALL PHASE 1 FOUNDATION TESTS PASSED SUCCESSFULLY! <<<\n")
