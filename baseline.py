"""
TrafficBaseline table — tracks per-source-IP rolling statistics
(mean and variance of packets-per-window) used for anomaly detection.

Updated incrementally using Welford's online algorithm, so we never
need to store or re-scan full traffic history to keep stats current.

Windows that already triggered a rule-based alert (PORT_SCAN,
DOS_ATTEMPT, SUSPICIOUS_PORT) are deliberately excluded from updating
this baseline — otherwise attack traffic would gradually poison the
model of what counts as "normal" for that IP.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from database import Base


class TrafficBaseline(Base):
    __tablename__ = "traffic_baseline"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, unique=True, index=True, nullable=False)

    sample_count = Column(Integer, default=0, nullable=False)
    mean_packet_count = Column(Float, default=0.0, nullable=False)

    # M2 is Welford's running sum-of-squared-differences — not variance
    # itself, but what variance is computed FROM. Storing it this way
    # (rather than variance directly) is what makes the incremental
    # update mathematically correct without needing full history.
    m2 = Column(Float, default=0.0, nullable=False)

    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())