from contextlib import asynccontextmanager
# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.api import health, investigations, evidence, timeline, machines, reports
from app.api import evasion
from app.api import websocket as ws_router
from app.api import telemetry

from app.services.retention import start_retention_loop
from app.services.live_telemetry import start_live_telemetry_loop
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database tables with retry
    import time
    for attempt in range(1, 4):
        try:
            init_db()
            print("[DB] Database tables verified/initialized successfully.")
            break
        except Exception as e:
            print(f"[DB] Attempt {attempt}/3 failed to initialize database: {e}")
            if attempt < 3:
                time.sleep(2)
            else:
                print("[DB] Warning: Continuing startup without synchronous table initialization.")

    # Start Free-Tier Retention Guardian and In-Process Live Telemetry
    retention_task = asyncio.create_task(start_retention_loop())
    telemetry_task = asyncio.create_task(start_live_telemetry_loop())

    yield
    # Clean shutdown
    retention_task.cancel()
    telemetry_task.cancel()
    try:
        await asyncio.gather(retention_task, telemetry_task, return_exceptions=True)
    except Exception:
        pass

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Adaptive Intent-Driven Digital Forensics Framework MVP",
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS
cors_origins = [o for o in settings.CORS_ORIGINS if o != "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else ["*"],
    allow_origin_regex=r"^https?://.*" if "*" in settings.CORS_ORIGINS else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router, prefix=settings.API_PREFIX)
app.include_router(investigations.router, prefix=settings.API_PREFIX)
app.include_router(evidence.router, prefix=settings.API_PREFIX)
app.include_router(timeline.router, prefix=settings.API_PREFIX)
app.include_router(machines.router, prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix=settings.API_PREFIX)
app.include_router(evasion.router, prefix=settings.API_PREFIX)
app.include_router(ws_router.router, prefix=settings.API_PREFIX)
app.include_router(telemetry.router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    return {
        "title": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_PREFIX}/health"
    }

if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
