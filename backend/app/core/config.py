import os
from pathlib import Path
from pydantic import BaseModel, Field

# Automatically load .env file if present
_backend_dir = Path(__file__).resolve().parent.parent.parent
_env_file = _backend_dir / ".env"
if _env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file)
    except Exception:
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip()
                    _v = _v.strip().strip("'\"")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v


def _resolve_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        return f"sqlite:///{_backend_dir / 'jocky.db'}"
    # Supabase & cloud providers often provide 'postgres://'; SQLAlchemy requires 'postgresql://'
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # Render and many cloud hosts do not have outbound IPv6.
    # Supabase direct host (db.<ref>.supabase.co:5432) resolves only to an IPv6 address,
    # causing psycopg2 to fail with: "port 5432 failed: Network is unreachable".
    # We automatically rewrite known Supabase direct hosts to the IPv4-compatible pooler:
    if "db.vxmzsltsdjysgfzshyrr.supabase.co" in url:
        url = url.replace("db.vxmzsltsdjysgfzshyrr.supabase.co:5432", "aws-0-ap-south-1.pooler.supabase.com:5432")
        url = url.replace("db.vxmzsltsdjysgfzshyrr.supabase.co", "aws-0-ap-south-1.pooler.supabase.com:5432")
        if "://postgres:" in url:
            url = url.replace("://postgres:", "://postgres.vxmzsltsdjysgfzshyrr:")
    
    # Auto-adapt driver prefix if user provides standard postgresql://
    if url.startswith("postgresql://") and not (url.startswith("postgresql+psycopg2://") or url.startswith("postgresql+psycopg://")):
        import importlib.util
        if importlib.util.find_spec("psycopg2") is not None:
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        elif importlib.util.find_spec("psycopg") is not None:
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _resolve_safe_scan_dir() -> Path:
    env_dir = os.getenv("SAFE_SCAN_DIR")
    if env_dir:
        return Path(env_dir)
    return _backend_dir.parent / "evidence" / "safe_scan"


class Settings(BaseModel):
    PROJECT_NAME: str = "JOCKY - Adaptive Intent-Driven Digital Forensics Framework"
    PROJECT_SLOGAN: str = "Adaptive Intent-to-Workflow Digital Forensics Framework"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # Path configurations
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    BACKEND_DIR: Path = _backend_dir
    
    # Database (Supabase PostgreSQL or local SQLite)
    DATABASE_URL: str = Field(default_factory=_resolve_database_url)
    
    # Artifact and Evidence Directories
    EVIDENCE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "evidence")
    DEMO_DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "demo_data")
    
    # Investigation constraints
    MAX_ROUNDS: int = Field(default_factory=lambda: int(os.getenv("MAX_ROUNDS", "3")))
    DEMO_MODE: bool = Field(default_factory=lambda: os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes"))
    
    # Safe directory for file forensics (prevent accidental full-drive scans)
    # Defaults to evidence/safe_scan directory inside the project.
    # Override with SAFE_SCAN_DIR env var to point at any specific investigation directory.
    SAFE_SCAN_DIR: Path = Field(default_factory=_resolve_safe_scan_dir)
    
    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

settings = Settings()

# Ensure critical directories exist
settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
settings.DEMO_DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.SAFE_SCAN_DIR.mkdir(parents=True, exist_ok=True)
