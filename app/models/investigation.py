from datetime import datetime

from pydantic import BaseModel


class InvestigationAction(BaseModel):
    action_id: str
    action_type: str
    performed_by: str
    performed_at: datetime
    target: str
    reason: str
    status: str


class Investigation(BaseModel):
    incident_id: str
    analyst: str | None = None
    status: str
    findings: list[str]
    actions: list[InvestigationAction]
    updated_at: datetime