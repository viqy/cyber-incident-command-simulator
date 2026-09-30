from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from app.core.reporting import (
    generate_incident_report,
    render_incident_report_html,
)
from app.core.simulator import create_credential_compromise_incident


router = APIRouter(
    prefix="/api/incidents",
    tags=["Reporting"],
)


@router.get("/{incident_id}/report")
def get_incident_report(
    incident_id: str,
):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    try:
        return generate_incident_report(
            incident_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/{incident_id}/report/export",
    response_class=HTMLResponse,
)
def export_incident_report(
    incident_id: str,
):
    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    try:
        report = generate_incident_report(
            incident_id
        )

        html = render_incident_report_html(
            report
        )

        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition": (
                    f'attachment; '
                    f'filename="{incident_id}-incident-report.html"'
                )
            },
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc