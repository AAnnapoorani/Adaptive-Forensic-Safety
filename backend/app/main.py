from contextlib import asynccontextmanager
# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.models.machine import Machine
from app.utils.platform import get_machine_info
from app.api import health, investigations, evidence, timeline, machines, reports
from app.api import evasion
from app.api import websocket as ws_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database tables
    init_db()
    
    # Auto-register current local machine
    db = SessionLocal()
    try:
        info = get_machine_info()
        existing = db.query(Machine).filter(
            (Machine.id == info["id"]) | (Machine.hostname == info["hostname"])
        ).first()
        if not existing:
            machine = Machine(
                id=info["id"],
                hostname=info["hostname"],
                os_name=info["os_name"],
                os_version=info["os_version"],
                architecture=info["architecture"],
                ip_address=info["ip_address"],
                status="ACTIVE"
            )
            db.add(machine)
            db.commit()
        else:
            existing.os_version = info["os_version"]
            existing.ip_address = info["ip_address"]
            setattr(existing, "status", "ACTIVE")
            db.commit()
    except Exception as e:
        print(f"Warning: Failed to auto-register machine: {e}")
    finally:
        db.close()

    yield
    # Shutdown logic if needed

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
