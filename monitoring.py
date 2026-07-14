"""
Routes for viewing traffic logs and alerts.
 
RBAC design for this project:
- admin, analyst -> can view raw traffic logs (sensitive, high volume)
- admin, analyst, viewer -> can view alerts (summarized, meant for wider visibility)
 
This mirrors a real SOC: junior/viewer-level staff usually see dashboards
and alerts, while raw packet-level data is restricted to people actually
investigating (analysts) or administering the system.
"""
 
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from datetime import datetime
 
from database import get_db
from logs import TrafficLog
from alerts import Alert
from auth import require_role
from encryption import decrypt_str

 
router = APIRouter(tags=["Monitoring"])
 
 
# ---------- Response schemas ----------
 
class TrafficLogOut(BaseModel):
    id: int
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: Optional[int]
    captured_at: datetime
 
    class Config:
        from_attributes = True
 
 
class AlertOut(BaseModel):
    id: int
    rule_type: str
    source_ip: str
    severity: str
    description: Optional[str]
    created_at: datetime
    geo_country: Optional[str]
    geo_city: Optional[str]
    geo_lat: Optional[float]
    geo_lon: Optional[float]
    geo_simulated: Optional[bool]

    class Config:
        from_attributes = True
 
 
# ---------- Routes ----------
 
@router.get("/logs", response_model=List[TrafficLogOut])
def get_logs(
    limit: int = Query(default=50, le=500),
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    """Raw packet logs — restricted to admin/analyst (higher sensitivity, higher volume)."""
    return (
        db.query(TrafficLog)
        .order_by(desc(TrafficLog.captured_at))
        .limit(limit)
        .all()
    )
 
 
@router.get("/alerts", response_model=List[AlertOut])
def get_alerts(
    limit: int = Query(default=50, le=500),
    db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Detected alerts — visible to all authenticated roles, including viewer."""
    results = (
        db.query(Alert)
        .order_by(desc(Alert.created_at))
        .limit(limit)
        .all()
    )
    # Descriptions are encrypted at rest (see encryption.py) — decrypt
    # them here so the API returns readable text to authorized users.
    for alert in results:
        alert.description = decrypt_str(alert.description)
        alert.geo_lat = float(alert.geo_lat) if alert.geo_lat is not None else None
        alert.geo_lon = float(alert.geo_lon) if alert.geo_lon is not None else None
        alert.geo_simulated = (alert.geo_simulated == "true") if alert.geo_simulated is not None else None
    return results