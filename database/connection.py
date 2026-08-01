import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Check if environment variable is set (Render production PostgreSQL)
RAW_DATABASE_URL = os.environ.get("DATABASE_URL")

if RAW_DATABASE_URL:
    # SQLAlchemy requires postgresql:// instead of postgres://
    if RAW_DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
    else:
        DATABASE_URL = RAW_DATABASE_URL
    engine = create_engine(DATABASE_URL)
else:
    # Fallback to local SQLite database
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "aegis.db")
    DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    
    # SQLite performance optimizations
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
