# Alembic migration environment.
# Reads the DATABASE_URL from the app's settings (.env) so there is a single
# source of truth for the database connection string.
# Imports app.models so Alembic can auto-detect schema changes.

import sys
import os

# ── Make sure the project root is on sys.path ──────────────────────────────────
# Required when running `alembic` from the project root directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ── Import app settings and models ────────────────────────────────────────────
# settings provides the DATABASE_URL from .env
from app.config import settings

# Import Base and ALL models so Alembic can see the full schema.
# Add any new model files here as the project grows.
from app.database import Base
import app.models  # noqa: F401 — registers all ORM models on Base.metadata

# ── Alembic Config object ──────────────────────────────────────────────────────
config = context.config

# Override the sqlalchemy.url from alembic.ini with the real URL from .env
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configure Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# MetaData object containing all table definitions — used for autogenerate
target_metadata = Base.metadata


# ── Offline migration (generates SQL without a live DB connection) ─────────────
def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode — generates raw SQL that can be reviewed
    and applied manually without a live database connection.

    Usage: `alembic upgrade head --sql`
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online migration (applies migrations to the live DB) ──────────────────────
def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode — connects to the live database and applies
    any pending migrations.

    Usage: `alembic upgrade head`
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Compare server defaults so Alembic detects DEFAULT value changes
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ── Entry point ───────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
