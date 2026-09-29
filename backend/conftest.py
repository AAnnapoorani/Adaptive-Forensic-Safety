# backend/conftest.py
"""
Pytest root configuration for JOCKY backend test suite.
Sets sys.path so all app imports resolve correctly without package install.
"""
import sys
import os
import inspect
import asyncio

# Add backend/ directory to sys.path so `from app.xxx import ...` works
sys.path.insert(0, os.path.dirname(__file__))


def pytest_pyfunc_call(pyfuncitem):
    """Support async def test functions even if pytest-asyncio is not installed."""
    testfunction = pyfuncitem.obj
    if inspect.iscoroutinefunction(testfunction):
        asyncio.run(testfunction(*[pyfuncitem.funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames]))
        return True

