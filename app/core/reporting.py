from datetime import datetime, timezone
from html import escape

from app.core.correlation import correlate_attack
from app.core.detection import detect_suspicious_activity
from app.core.investigation_repository import (
    get_or_create_investigation,
)
from app.core.simulator import (
    create_credential_compromise_incident,
)
from app.models.report import IncidentReport


def generate_incident_report(
    incident_id: str,
) -> IncidentReport:

    incident = create_credential_compromise_incident()

    if incident.incident_id != incident_id:
        raise ValueError("Incident not found.")

    detections = detect_suspicious_activity(
        incident.events
    )

    attack_chain = correlate_attack(
        incident.incident_id,
        incident.events,
        detections,
    )

    investigation = get_or_create_investigation(
        incident_id
    )

    if investigation.findings:
        findings_summary = " ".join(
            investigation.findings
        )
    else:
        findings_summary = (
            "No investigation findings have been recorded."
        )

    executive_summary = (
        f"The {incident.name} affected "
        f"{incident.affected_host} and user "
        f"{incident.affected_user}. "
        f"The investigation identified "
        f"{len(detections)} security detections across "
        f"{len(incident.events)} security events. "
        f"The correlated attack chain was assessed with "
        f"{attack_chain.confidence} confidence. "
        f"{findings_summary}"
    )

    response_actions = [
        (
            f"{action.action_type}: "
            f"{action.target} "
            f"({action.status})"
        )
        for action in investigation.actions
    ]

    return IncidentReport(
        incident_id=incident.incident_id,
        incident_name=incident.name,
        severity=incident.severity,
        status=investigation.status,
        affected_host=incident.affected_host,
        affected_user=incident.affected_user,
        executive_summary=executive_summary,
        attack_type=attack_chain.attack_type,
        confidence=attack_chain.confidence,
        event_count=len(incident.events),
        detection_count=len(detections),
        attack_stages=[
            stage.stage
            for stage in attack_chain.stages
        ],
        findings=investigation.findings,
        response_actions=response_actions,
        analyst=investigation.analyst,
        generated_at=datetime.now(timezone.utc),
    )


def render_incident_report_html(
    report: IncidentReport,
) -> str:

    findings_html = ""

    if report.findings:
        findings_html = "".join(
            f"<li>{escape(finding)}</li>"
            for finding in report.findings
        )
    else:
        findings_html = (
            "<li>No investigation findings have been recorded.</li>"
        )

    stages_html = ""

    if report.attack_stages:
        stages_html = "".join(
            f"<li><strong>{escape(stage)}</strong></li>"
            for stage in report.attack_stages
        )
    else:
        stages_html = "<li>No attack stages recorded.</li>"

    actions_html = ""

    if report.response_actions:
        actions_html = "".join(
            f"<li>{escape(action)}</li>"
            for action in report.response_actions
        )
    else:
        actions_html = "<li>No response actions recorded.</li>"

    analyst = (
        escape(report.analyst)
        if report.analyst
        else "Not assigned"
    )

    generated_at = escape(
        report.generated_at.isoformat()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>
        {escape(report.incident_id)} - Incident Report
    </title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 40px;
            background: #f4f6f8;
            color: #1f2937;
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }}

        .header {{
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 24px;
            margin-bottom: 30px;
        }}

        .header h1 {{
            margin: 0 0 8px;
            font-size: 30px;
        }}

        .header p {{
            margin: 4px 0;
            color: #6b7280;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}

        .card {{
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 18px;
            background: #fafafa;
        }}

        .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #6b7280;
            margin-bottom: 6px;
        }}

        .value {{
            font-size: 18px;
            font-weight: 600;
        }}

        .section {{
            margin-top: 32px;
        }}

        .section h2 {{
            font-size: 21px;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 8px;
        }}

        .summary {{
            background: #f9fafb;
            border-left: 4px solid #374151;
            padding: 20px;
            border-radius: 4px;
        }}

        ul {{
            padding-left: 24px;
        }}

        li {{
            margin-bottom: 8px;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            font-size: 12px;
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .container {{
                box-shadow: none;
                max-width: none;
            }}
        }}

        @media (max-width: 700px) {{
            body {{
                padding: 15px;
            }}

            .container {{
                padding: 20px;
            }}

            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>

<body>

<div class="container">

    <div class="header">
        <h1>Cyber Incident Report</h1>

        <p>
            Incident ID:
            <strong>{escape(report.incident_id)}</strong>
        </p>

        <p>
            Generated:
            {generated_at}
        </p>
    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Incident</div>
            <div class="value">
                {escape(report.incident_name)}
            </div>
        </div>

        <div class="card">
            <div class="label">Severity</div>
            <div class="value">
                {escape(report.severity)}
            </div>
        </div>

        <div class="card">
            <div class="label">Status</div>
            <div class="value">
                {escape(report.status)}
            </div>
        </div>

        <div class="card">
            <div class="label">Analyst</div>
            <div class="value">
                {analyst}
            </div>
        </div>

        <div class="card">
            <div class="label">Affected Host</div>
            <div class="value">
                {escape(report.affected_host)}
            </div>
        </div>

        <div class="card">
            <div class="label">Affected User</div>
            <div class="value">
                {escape(report.affected_user)}
            </div>
        </div>

        <div class="card">
            <div class="label">Security Events</div>
            <div class="value">
                {report.event_count}
            </div>
        </div>

        <div class="card">
            <div class="label">Detections</div>
            <div class="value">
                {report.detection_count}
            </div>
        </div>

    </div>

    <div class="section">
        <h2>Executive Summary</h2>

        <div class="summary">
            {escape(report.executive_summary)}
        </div>
    </div>

    <div class="section">
        <h2>Attack Assessment</h2>

        <p>
            <strong>Attack Type:</strong>
            {escape(report.attack_type)}
        </p>

        <p>
            <strong>Correlation Confidence:</strong>
            {escape(report.confidence)}
        </p>
    </div>

    <div class="section">
        <h2>Attack Chain</h2>

        <ul>
            {stages_html}
        </ul>
    </div>

    <div class="section">
        <h2>Investigation Findings</h2>

        <ul>
            {findings_html}
        </ul>
    </div>

    <div class="section">
        <h2>Response Actions</h2>

        <ul>
            {actions_html}
        </ul>
    </div>

    <div class="footer">
        Cyber Incident Command Simulator<br>
        Synthetic defensive cybersecurity exercise.
        This report contains simulated incident data.
    </div>

</div>

</body>
</html>
"""