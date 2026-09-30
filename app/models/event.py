from datetime import datetime
from pydantic import BaseModel


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    host: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process: str | None = None
    command: str | None = None
    domain: str | None = None
    description: str