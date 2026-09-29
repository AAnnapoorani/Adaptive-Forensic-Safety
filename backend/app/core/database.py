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
    """Initialize all tables and migrate new columns safely."""
    # Import models here to ensure they are registered with Base metadata
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Lightweight migration for existing SQLite / Postgres tables
    with engine.begin() as conn:
        try:
            # Check machine_processes columns
            from sqlalchemy import inspect, text
            inspector = inspect(engine)
            cols = [c["name"] for c in inspector.get_columns("machine_processes")]
            if "threat_level" not in cols:
                conn.execute(text("ALTER TABLE machine_processes ADD COLUMN threat_level VARCHAR(32) DEFAULT 'CLEAN'"))
            if "matched_rules_json" not in cols:
                conn.execute(text("ALTER TABLE machine_processes ADD COLUMN matched_rules_json TEXT"))

            # Check machines table columns
            m_cols = [c["name"] for c in inspector.get_columns("machines")]
            if "machine_id" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN machine_id VARCHAR(64)"))
            if "os_type" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN os_type VARCHAR(32) DEFAULT 'Windows'"))
            if "mac_address" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN mac_address VARCHAR(64)"))
            if "agent_version" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN agent_version VARCHAR(32) DEFAULT '1.0.0'"))
            if "first_seen" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN first_seen TIMESTAMP"))
            if "metadata_json" not in m_cols:
                conn.execute(text("ALTER TABLE machines ADD COLUMN metadata_json TEXT"))
        except Exception as e:
            # Table might not exist yet or dialect syntax difference, create_all already handled it
            pass
