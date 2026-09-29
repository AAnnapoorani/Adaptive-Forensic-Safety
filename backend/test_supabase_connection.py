"""
test_supabase_connection.py
Quick diagnostic script to verify live Supabase PostgreSQL connectivity.

Usage:
    python test_supabase_connection.py
"""

import sys
from pathlib import Path
# pyrefly: ignore [missing-import]
from sqlalchemy import create_engine, text

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings  # noqa: E402
from app.core.database import Base, init_db  # noqa: E402


def main():
    print("=" * 70)
    print(" JOCKY -- SUPABASE CONNECTIVITY DIAGNOSTIC")
    print("=" * 70)

    db_url = settings.DATABASE_URL
    if not db_url:
        print("\n[-] ERROR: DATABASE_URL is not set in backend/.env.")
        return

    # Normalize dialect schema for SQLAlchemy if postgres:// is used
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    print(f"\n[+] Raw Configured URL: {db_url.split('@')[-1] if '@' in db_url else db_url}")

    if "sqlite" in db_url:
        print("\n[-] NOTICE: Current DATABASE_URL is pointing to local SQLite.")
        print("    To test Supabase, set DATABASE_URL in backend/.env to your Supabase URI.")
        print("    Format: postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres\n")
        return

    if "[YOUR-PASSWORD]" in db_url or "[YOUR-PROJECT-REF]" in db_url:
        print("\n[-] ERROR: Your backend/.env still contains placeholder text ([YOUR-PASSWORD]).")
        print("    Please replace with your real Supabase project password and reference.\n")
        return

    print("\n[+] Attempting connection to Supabase PostgreSQL...")
    engine = None
    try:
        engine = create_engine(
            db_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 10},
        )
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version();")).scalar()
            print("[OK] SUCCESS: Connected to Supabase!")
            print(f"     Server Version: {result}")

            # Test schema creation / initialization
            print("\n[+] Initializing JOCKY tables on Supabase...")
            init_db()
            Base.metadata.create_all(bind=engine)
            conn.commit()

            # Check tables created
            tables_res = conn.execute(text(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;"
            )).fetchall()
            table_names = [t[0] for t in tables_res]
            print(f"[OK] Active Tables in Supabase ({len(table_names)}):")
            for t in table_names:
                print(f"      - {t}")

        print("\n" + "=" * 70)
        print(" ALL CHECKS PASSED: Your JOCKY framework is 100% connected to Supabase!")
        print("=" * 70)
    except Exception as e:
        print(f"\n[!] CONNECTION FAILED: {e}")
        print("\nCommon Troubleshooting Tips:")
        print(" 1. Password check: If your password has special characters like '@' or '#', URL-encode them.")
        print(" 2. Network check: If IPv6 is not supported by your network, use the Supabase Pooler URI on port 6543.")
        print(" 3. Driver check: Make sure psycopg2-binary is installed: pip install psycopg2-binary")
        sys.exit(1)
    finally:
        if engine:
            engine.dispose()


if __name__ == "__main__":
    main()

