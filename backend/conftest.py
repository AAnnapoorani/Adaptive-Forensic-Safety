# backend/conftest.py
"""
Pytest root configuration for JOCKY backend test suite.
Sets sys.path so all app imports resolve correctly without package install.
Ensures an isolated test database is used so the developer's jocky.db is never polluted.
"""
import sys
import os
import inspect
import asyncio
from pathlib import Path
import pytest

_backend_dir = Path(__file__).resolve().parent
_test_db_file = _backend_dir / "test_suite.db"

# Force test database for all pytest runs unless explicitly overridden
if "DATABASE_URL" not in os.environ or os.environ.get("DATABASE_URL") == "sqlite:///:memory:":
    os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_file.as_posix()}"

# Add backend/ directory to sys.path so `from app.xxx import ...` works
sys.path.insert(0, str(_backend_dir))


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Ensure a fresh database schema for the test session and clean up after."""
    from app.core.database import init_db, engine
    init_db()
    yield
    # Cleanup test db connection and file after all tests finish
    try:
        engine.dispose()
        if _test_db_file.exists():
            _test_db_file.unlink(missing_ok=True)
    except Exception:
        pass


def pytest_pyfunc_call(pyfuncitem):
    """Support async def test functions even if pytest-asyncio is not installed."""
    testfunction = pyfuncitem.obj
    if inspect.iscoroutinefunction(testfunction):
        asyncio.run(testfunction(*[pyfuncitem.funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames]))
        return True

