"""The initial revision is a reproducible snapshot of the application schema."""

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import NullPool

from app.config import settings
from app.db import Base
import app.models  # noqa: F401 - register all mapped tables


def test_initial_migration_matches_models_and_downgrades(tmp_path, monkeypatch):
    database_url = f"sqlite:///{(tmp_path / 'migration.sqlite3').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    settings.cache_clear()
    backend_dir = Path(__file__).resolve().parents[1]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "alembic"))
    engine = create_engine(database_url, poolclass=NullPool)
    try:
        command.upgrade(config, "head")
        with engine.connect() as connection:
            tables = set(inspect(connection).get_table_names())
            assert tables - {"alembic_version"} == set(Base.metadata.tables)
            assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []

        command.downgrade(config, "base")
        with engine.connect() as connection:
            assert set(inspect(connection).get_table_names()) - {"alembic_version"} == set()
    finally:
        engine.dispose()
        settings.cache_clear()
