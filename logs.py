from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True, nullable=False)
    destination_ip = Column(String, index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, index=True, nullable=True)
    protocol = Column(String, nullable=False)  # e.g. "TCP", "UDP", "ICMP"
    packet_size = Column(Integer, nullable=True)  # bytes, useful for DoS detection later
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
