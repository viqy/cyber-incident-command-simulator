from datetime import datetime, timezone

from app.models.investigation import (
    Investigation,
    InvestigationAction,
)


VALID_STATUSES = [
    "DETECTED",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
    "CLOSED",
]


VALID_ACTIONS = [
    "ISOLATE_HOST",
    "DISABLE_ACCOUNT",
    "BLOCK_DOMAIN",
    "PRESERVE_EVIDENCE",
    "ESCALATE",
]


def create_investigation(incident_id: str) -> Investigation:
    return Investigation(
        incident_id=incident_id,
        analyst=None,
        status="DETECTED",
        findings=[],
        actions=[],
        updated_at=datetime.now(timezone.utc),
    )


def update_investigation_status(
    investigation: Investigation,
    status: str,
) -> Investigation:

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid investigation status: {status}"
        )

    investigation.status = status
    investigation.updated_at = datetime.now(timezone.utc)

    return investigation


def add_finding(
    investigation: Investigation,
    finding: str,
) -> Investigation:

    if not finding.strip():
        raise ValueError("Finding cannot be empty.")

    investigation.findings.append(finding.strip())
    investigation.updated_at = datetime.now(timezone.utc)

    return investigation


def perform_action(
    investigation: Investigation,
    action_type: str,
    performed_by: str,
    target: str,
    reason: str,
) -> Investigation:

    if action_type not in VALID_ACTIONS:
        raise ValueError(
            f"Invalid investigation action: {action_type}"
        )

    if not performed_by.strip():
        raise ValueError("performed_by cannot be empty.")

    if not target.strip():
        raise ValueError("target cannot be empty.")

    if not reason.strip():
        raise ValueError("reason cannot be empty.")

    action = InvestigationAction(
        action_id=f"ACT-{len(investigation.actions) + 1:04d}",
        action_type=action_type,
        performed_by=performed_by.strip(),
        performed_at=datetime.now(timezone.utc),
        target=target.strip(),
        reason=reason.strip(),
        status="COMPLETED",
    )

    investigation.actions.append(action)
    investigation.updated_at = datetime.now(timezone.utc)

    return investigation