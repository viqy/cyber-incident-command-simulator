from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.investigation import (
    VALID_ACTIONS,
    VALID_STATUSES,
    add_finding,
    perform_action,
)
from app.core.investigation_repository import (
    add_action,
    add_finding as save_finding,
    get_or_create_investigation,
    update_status,
)
from app.core.simulator import create_credential_compromise_incident


router = APIRouter(
    prefix="/api/incidents",
    tags=["Investigation"],
)


class StatusUpdateRequest(BaseModel):
    status: str


class FindingRequest(BaseModel):
    finding: str


class ActionRequest(BaseModel):
    action_type: str
    performed_by: str
    target: str
    reason: str


def get_investigation_or_404(
    incident_id: str,
):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return get_or_create_investigation(incident_id)


@router.get("/{incident_id}/investigation")
def get_investigation(
    incident_id: str,
):
    return get_investigation_or_404(incident_id)


@router.post("/{incident_id}/investigation/status")
def change_investigation_status(
    incident_id: str,
    request: StatusUpdateRequest,
):
    investigation = get_investigation_or_404(incident_id)

    if request.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid investigation status: {request.status}",
        )

    update_status(
        incident_id,
        request.status,
    )

    return get_or_create_investigation(incident_id)


@router.post("/{incident_id}/investigation/findings")
def create_finding(
    incident_id: str,
    request: FindingRequest,
):
    get_investigation_or_404(incident_id)

    try:
        finding = request.finding.strip()

        if not finding:
            raise ValueError(
                "Finding cannot be empty."
            )

        save_finding(
            incident_id,
            finding,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return get_or_create_investigation(incident_id)


@router.post("/{incident_id}/investigation/actions")
def create_action(
    incident_id: str,
    request: ActionRequest,
):
    investigation = get_investigation_or_404(incident_id)

    if request.action_type not in VALID_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid investigation action: {request.action_type}",
        )

    if not request.performed_by.strip():
        raise HTTPException(
            status_code=400,
            detail="performed_by cannot be empty.",
        )

    if not request.target.strip():
        raise HTTPException(
            status_code=400,
            detail="target cannot be empty.",
        )

    if not request.reason.strip():
        raise HTTPException(
            status_code=400,
            detail="reason cannot be empty.",
        )

    action_number = len(investigation.actions) + 1

    from datetime import datetime, timezone

    action = {
        "action_id": f"ACT-{action_number:04d}",
        "action_type": request.action_type,
        "performed_by": request.performed_by.strip(),
        "performed_at": datetime.now(timezone.utc),
        "target": request.target.strip(),
        "reason": request.reason.strip(),
        "status": "COMPLETED",
    }

    from app.models.investigation import InvestigationAction

    investigation_action = InvestigationAction(
        **action
    )

    add_action(
        incident_id,
        investigation_action,
    )

    return get_or_create_investigation(incident_id)