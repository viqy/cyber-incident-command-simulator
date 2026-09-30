from datetime import datetime, timezone

from app.database.database import get_connection
from app.models.investigation import (
    Investigation,
    InvestigationAction,
)


def get_or_create_investigation(
    incident_id: str,
) -> Investigation:

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                incident_id,
                analyst,
                status,
                updated_at
            FROM investigations
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

        if row is None:
            now = datetime.now(timezone.utc)

            connection.execute(
                """
                INSERT INTO investigations (
                    incident_id,
                    analyst,
                    status,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    incident_id,
                    None,
                    "DETECTED",
                    now.isoformat(),
                ),
            )

            connection.commit()

            analyst = None
            status = "DETECTED"
            updated_at = now

        else:
            analyst = row["analyst"]
            status = row["status"]
            updated_at = datetime.fromisoformat(
                row["updated_at"]
            )

        findings_rows = connection.execute(
            """
            SELECT finding
            FROM findings
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()

        findings = [
            row["finding"]
            for row in findings_rows
        ]

        action_rows = connection.execute(
            """
            SELECT
                action_id,
                action_type,
                performed_by,
                performed_at,
                target,
                reason,
                status
            FROM actions
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()

        actions = [
            InvestigationAction(
                action_id=row["action_id"],
                action_type=row["action_type"],
                performed_by=row["performed_by"],
                performed_at=datetime.fromisoformat(
                    row["performed_at"]
                ),
                target=row["target"],
                reason=row["reason"],
                status=row["status"],
            )
            for row in action_rows
        ]

        return Investigation(
            incident_id=incident_id,
            analyst=analyst,
            status=status,
            findings=findings,
            actions=actions,
            updated_at=updated_at,
        )

    finally:
        connection.close()


def update_status(
    incident_id: str,
    status: str,
) -> Investigation:

    now = datetime.now(timezone.utc)

    connection = get_connection()

    try:
        connection.execute(
            """
            UPDATE investigations
            SET status = ?,
                updated_at = ?
            WHERE incident_id = ?
            """,
            (
                status,
                now.isoformat(),
                incident_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return get_or_create_investigation(incident_id)


def add_finding(
    incident_id: str,
    finding: str,
) -> Investigation:

    now = datetime.now(timezone.utc)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO findings (
                incident_id,
                finding,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                incident_id,
                finding,
                now.isoformat(),
            ),
        )

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE incident_id = ?
            """,
            (
                now.isoformat(),
                incident_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return get_or_create_investigation(incident_id)


def add_action(
    incident_id: str,
    action: InvestigationAction,
) -> Investigation:

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO actions (
                action_id,
                incident_id,
                action_type,
                performed_by,
                performed_at,
                target,
                reason,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action.action_id,
                incident_id,
                action.action_type,
                action.performed_by,
                action.performed_at.isoformat(),
                action.target,
                action.reason,
                action.status,
            ),
        )

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE incident_id = ?
            """,
            (
                action.performed_at.isoformat(),
                incident_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return get_or_create_investigation(incident_id)