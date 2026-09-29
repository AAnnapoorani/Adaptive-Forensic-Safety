from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        echo=False
    )
else:
    # Supabase / PostgreSQL cloud configuration with connection pooling & ping
    engine = create_engine(
        db_url,
        pool_pre_ping=True,  # Auto-reconnect if cloud connection was closed
        pool_recycle=300,    # Recycle connections periodically
        pool_size=10,
        max_overflow=20,
        echo=False
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:
    """Initialize all tables."""
    # Import models here to ensure they are registered with Base metadata
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
