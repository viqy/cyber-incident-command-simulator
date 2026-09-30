from datetime import datetime

from pydantic import BaseModel


class IncidentReport(BaseModel):
    incident_id: str
    incident_name: str
    severity: str
    status: str
    affected_host: str
    affected_user: str

    executive_summary: str

    attack_type: str
    confidence: str

    event_count: int
    detection_count: int

    attack_stages: list[str]
    findings: list[str]

    response_actions: list[str]

    analyst: str | None = None
    generated_at: datetime