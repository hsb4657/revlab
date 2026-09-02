from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import SQLALCHEMY_DATABASE_URL

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)


@event.listens_for(engine, "connect")
def _configure_sqlite_connection(connection, _record):
    """Make concurrent task updates less likely to fail with SQLite locks."""
    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()
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
        "definition_snapshot": "JSON DEFAULT '{}'",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE graph_tasks ADD COLUMN {name} {definition}"))


# Migrate legacy local databases on import as well as during application
# startup.  CLI tools, tests, and MCP integrations can open SessionLocal
# without constructing the FastAPI app first, so startup-only migration would
# leave those callers unable to persist newer GraphTask fields.
_ensure_legacy_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
