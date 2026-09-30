from fastapi import APIRouter, HTTPException

from app.core.correlation import correlate_attack
from app.core.detection import detect_suspicious_activity
from app.core.simulator import create_credential_compromise_incident

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("")
def list_incidents():
    incident = create_credential_compromise_incident()

    return {
        "incidents": [
            {
                "incident_id": incident.incident_id,
                "name": incident.name,
                "severity": incident.severity,
                "status": incident.status,
                "affected_host": incident.affected_host,
                "affected_user": incident.affected_user,
            }
        ]
    }


@router.get("/{incident_id}")
def get_incident(incident_id: str):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


@router.get("/{incident_id}/events")
def get_incident_events(incident_id: str):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "incident_id": incident.incident_id,
        "events": incident.events,
    }


@router.get("/{incident_id}/detections")
def get_incident_detections(incident_id: str):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    detections = detect_suspicious_activity(incident.events)

    return {
        "incident_id": incident.incident_id,
        "detections": detections,
    }


@router.get("/{incident_id}/attack-chain")
def get_attack_chain(incident_id: str):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    detections = detect_suspicious_activity(incident.events)

    attack_chain = correlate_attack(
        incident.incident_id,
        incident.events,
        detections,
    )

    return attack_chain