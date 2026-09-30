from pydantic import BaseModel

from app.models.event import SecurityEvent


class Detection(BaseModel):
    detection_id: str
    rule_name: str
    severity: str
    event_id: str
    host: str
    user: str | None = None
    description: str


def detect_suspicious_activity(
    events: list[SecurityEvent],
) -> list[Detection]:
    detections: list[Detection] = []

    for event in events:

        # Rule 1: Office application spawning PowerShell
        if (
            event.event_type == "process_creation"
            and event.process == "powershell.exe"
            and "Microsoft Word" in event.description
        ):
            detections.append(
                Detection(
                    detection_id=f"DET-{len(detections) + 1:04d}",
                    rule_name="Office Application Spawned PowerShell",
                    severity="HIGH",
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user,
                    description=(
                        "Microsoft Word spawned a PowerShell process. "
                        "This behaviour requires investigation."
                    ),
                )
            )

        # Rule 2: Encoded PowerShell command
        if (
            event.event_type == "powershell"
            and event.command == "EncodedCommand"
        ):
            detections.append(
                Detection(
                    detection_id=f"DET-{len(detections) + 1:04d}",
                    rule_name="Encoded PowerShell Command",
                    severity="HIGH",
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user,
                    description=(
                        "PowerShell executed an encoded command."
                    ),
                )
            )

        # Rule 3: Suspicious DNS query
        if (
            event.event_type == "dns"
            and event.domain
            and event.domain.endswith(".example")
        ):
            detections.append(
                Detection(
                    detection_id=f"DET-{len(detections) + 1:04d}",
                    rule_name="Suspicious External DNS Query",
                    severity="MEDIUM",
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user,
                    description=(
                        f"Host queried suspicious domain {event.domain}."
                    ),
                )
            )

        # Rule 4: SMB lateral movement
        if (
            event.event_type == "network_connection"
            and event.destination_ip
        ):
            detections.append(
                Detection(
                    detection_id=f"DET-{len(detections) + 1:04d}",
                    rule_name="Potential SMB Lateral Movement",
                    severity="HIGH",
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user,
                    description=(
                        "An internal SMB connection was detected."
                    ),
                )
            )

        # Rule 5: Possible data exfiltration
        if event.event_type == "data_transfer":
            detections.append(
                Detection(
                    detection_id=f"DET-{len(detections) + 1:04d}",
                    rule_name="Potential Data Exfiltration",
                    severity="CRITICAL",
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user,
                    description=(
                        "Large outbound data transfer detected."
                    ),
                )
            )

    return detections