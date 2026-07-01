# Sets up the SQLAlchemy database engine, session factory, and declarative base.
# All models should inherit from `Base`. Use `get_db` as a FastAPI dependency
# to get a database session that is automatically closed after each request.

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

# Engine connects to MySQL using the URL from .env
engine = create_engine(settings.DATABASE_URL)

# SessionLocal is the factory for individual DB sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    # All ORM models inherit from this base class
    pass


def get_db():
    # Yields a DB session per request and ensures it's closed afterward
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
