import pytest
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import Base
from app.models.machine import Machine
from app.models.investigation import Investigation
from app.services.auto_triage import AutoTriageService, _COOLDOWN_MAP

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    
    # Pre-register a machine
    m = Machine(
        id="SUVADU-TESTHOST01",
        machine_id="SUVADU-TESTHOST01",
        hostname="TEST-WORKSTATION",
        os_type="Windows",
        os_name="Windows 11 Pro",
        status="ONLINE"
    )
    db.add(m)
    db.commit()
    
    yield db
    db.close()


def test_auto_triage_clean_telemetry(test_db):
    """Clean telemetry should not trigger an investigation."""
    _COOLDOWN_MAP.clear()
    metrics = SimpleNamespace(cpu_percent=15.0, memory_percent=40.0)
    procs = [{"pid": 100, "name": "explorer.exe", "threat_level": "CLEAN"}]
    events = []
    
    res = AutoTriageService.evaluate_telemetry(
        db=test_db,
        machine_id="SUVADU-TESTHOST01",
        metrics=metrics,
        processes=procs,
        events=events
    )
    assert res is None
    assert test_db.query(Investigation).count() == 0


def test_auto_triage_critical_process_triggers_investigation(test_db):
    """Critical process threat should trigger an autonomous investigation."""
    _COOLDOWN_MAP.clear()
    metrics = SimpleNamespace(cpu_percent=94.5, memory_percent=70.0)
    procs = [
        {"pid": 4412, "name": "mimikatz.exe", "threat_level": "CRITICAL", "matched_rules": ["In-Memory Injection Anomaly"]}
    ]
    events = []

    res = AutoTriageService.evaluate_telemetry(
        db=test_db,
        machine_id="SUVADU-TESTHOST01",
        metrics=metrics,
        processes=procs,
        events=events
    )
    assert res is not None
    assert res["triggered"] is True
    assert res["intent"] == "memory_injection_hunt"
    assert "Critical process observed: mimikatz.exe" in res["reason"]

    # Verify database persistence
    inv = test_db.query(Investigation).filter(Investigation.id == res["investigation_id"]).first()
    assert inv is not None
    assert inv.machine_id == "SUVADU-TESTHOST01"
    assert inv.intent == "memory_injection_hunt"


def test_auto_triage_cooldown_prevention(test_db):
    """Subsequent breaches within cooldown period must be rate-limited."""
    metrics = SimpleNamespace(cpu_percent=95.0, memory_percent=80.0)
    procs = [{"pid": 5512, "name": "rtcore64_exploit.exe", "threat_level": "CRITICAL", "matched_rules": ["BYOVD Driver Exploit"]}]

    # Second call should be blocked by cooldown
    res2 = AutoTriageService.evaluate_telemetry(
        db=test_db,
        machine_id="SUVADU-TESTHOST01",
        metrics=metrics,
        processes=procs,
        events=[]
    )
    assert res2 is None
