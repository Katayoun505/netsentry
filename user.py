"""
User table definition.
Roles: admin, analyst, viewer (used later for RBAC in Phase 6)
"""

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="viewer", nullable=False)  # admin | analyst | viewer
    created_at = Column(DateTime(timezone=True), server_default=func.now())