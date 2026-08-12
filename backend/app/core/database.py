from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import SQLALCHEMY_DATABASE_URL

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()


def init_db():
    from ..models import sample  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _ensure_legacy_columns()


def _ensure_legacy_columns():
    """Additive compatibility migration for databases created before GraphTask fields."""
    if not SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "graph_tasks" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("graph_tasks")}
    additions = {
        "sample_id": "INTEGER DEFAULT 0",
        "workflow_version": "VARCHAR(64) DEFAULT ''",
        "status_version": "INTEGER DEFAULT 0",
        "cancel_requested": "INTEGER DEFAULT 0",
        "heartbeat_at": "DATETIME",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE graph_tasks ADD COLUMN {name} {definition}"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
