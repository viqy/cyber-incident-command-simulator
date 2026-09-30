from datetime import datetime, timedelta, timezone

from app.models.event import SecurityEvent


def generate_credential_compromise_events() -> list[SecurityEvent]:
    start = datetime(2026, 9, 30, 9, 12, tzinfo=timezone.utc)

    events = [
        SecurityEvent(
            event_id="EVT-0001",
            timestamp=start,
            event_type="authentication",
            host="WS-FIN-042",
            user="j.smith",
            source_ip="10.10.20.55",
            description="Successful user authentication from workstation",
        ),
        SecurityEvent(
            event_id="EVT-0002",
            timestamp=start + timedelta(minutes=2),
            event_type="process_creation",
            host="WS-FIN-042",
            user="j.smith",
            process="powershell.exe",
            description="PowerShell process started by Microsoft Word",
        ),
        SecurityEvent(
            event_id="EVT-0003",
            timestamp=start + timedelta(minutes=3),
            event_type="powershell",
            host="WS-FIN-042",
            user="j.smith",
            process="powershell.exe",
            command="EncodedCommand",
            description="PowerShell executed an encoded command",
        ),
        SecurityEvent(
            event_id="EVT-0004",
            timestamp=start + timedelta(minutes=5),
            event_type="dns",
            host="WS-FIN-042",
            user="j.smith",
            domain="update-service.example",
            description="Workstation queried a suspicious external domain",
        ),
        SecurityEvent(
            event_id="EVT-0005",
            timestamp=start + timedelta(minutes=9),
            event_type="authentication",
            host="FILE-SRV-01",
            user="j.smith",
            source_ip="10.10.20.55",
            description="Successful administrative authentication to file server",
        ),
        SecurityEvent(
            event_id="EVT-0006",
            timestamp=start + timedelta(minutes=11),
            event_type="network_connection",
            host="WS-FIN-042",
            user="j.smith",
            source_ip="10.10.20.55",
            destination_ip="10.10.10.20",
            description="SMB connection established with internal file server",
        ),
        SecurityEvent(
            event_id="EVT-0007",
            timestamp=start + timedelta(minutes=16),
            event_type="data_transfer",
            host="WS-FIN-042",
            user="j.smith",
            destination_ip="203.0.113.50",
            description="Large outbound transfer detected",
        ),
    ]

    return events