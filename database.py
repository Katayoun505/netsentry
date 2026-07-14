"""
Database connection setup using SQLAlchemy.
Using SQLite for development — swap DATABASE_URL for PostgreSQL in production
e.g. "postgresql://user:password@localhost/netsentry_db"
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./siem.db"

# check_same_thread=False is only needed for SQLite (not for Postgres)
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Dependency used by FastAPI routes to get a DB session
    and guarantee it closes after the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
