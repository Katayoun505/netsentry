"""
Alert table — one row per triggered detection rule.
Kept separate from TrafficLog because volume differs wildly: you
might capture 10,000 packets but generate only a handful of alerts. This
mirrors how real SOC tools separate raw events from correlated incidents.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    # Which detection rule fired — keep these as short machine-readable codes,
    # e.g. "PORT_SCAN", "DOS_ATTEMPT", "SUSPICIOUS_PORT"
    rule_type = Column(String, index=True, nullable=False)

    source_ip = Column(String, index=True, nullable=False)

    # --- GeoIP fields (Phase 7) ---
    # Stored as String (not Float/Boolean) to avoid needing a migration
    # tool like Alembic on an existing SQLite table. Parsed to real
    # types on the way out in monitoring.py.
    geo_country = Column(String, nullable=True)
    geo_city = Column(String, nullable=True)
    geo_lat = Column(String, nullable=True)
    geo_lon = Column(String, nullable=True)
    geo_simulated = Column(String, nullable=True)  # "true" / "false"

    # "low" | "medium" | "high" | "critical" — keep it a plain string for now;
    # you can tighten this to an Enum later once you're comfortable with SQLAlchemy
    severity = Column(String, default="medium", nullable=False)

    # Human-readable explanation, e.g. "42 distinct ports contacted in 8 seconds"
    description = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)