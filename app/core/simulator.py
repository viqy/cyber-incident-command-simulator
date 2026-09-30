from app.models.incident import Incident
from app.scenarios.credential_compromise import (
    generate_credential_compromise_events,
)


def create_credential_compromise_incident() -> Incident:
    events = generate_credential_compromise_events()

    return Incident(
        incident_id="INC-2026-0001",
        name="Credential Compromise Simulation",
        severity="HIGH",
        status="DETECTED",
        created_at=events[0].timestamp,
        affected_host="WS-FIN-042",
        affected_user="j.smith",
        events=events,
    )