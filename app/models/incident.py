from datetime import datetime
from pydantic import BaseModel

from app.models.event import SecurityEvent


class Incident(BaseModel):
    incident_id: str
    name: str
    severity: str
    status: str
    created_at: datetime
    affected_host: str
    affected_user: str
    events: list[SecurityEvent]