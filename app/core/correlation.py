from pydantic import BaseModel

from app.core.detection import Detection
from app.models.event import SecurityEvent


class AttackStage(BaseModel):
    stage: str
    timestamp: str
    event_id: str
    detection_id: str
    description: str


class AttackChain(BaseModel):
    incident_id: str
    attack_type: str
    confidence: str
    stages: list[AttackStage]


def correlate_attack(
    incident_id: str,
    events: list[SecurityEvent],
    detections: list[Detection],
) -> AttackChain:
    event_map = {event.event_id: event for event in events}

    stages: list[AttackStage] = []

    stage_mapping = {
        "Office Application Spawned PowerShell": "Initial Execution",
        "Encoded PowerShell Command": "Command Execution",
        "Suspicious External DNS Query": "Command & Control",
        "Potential SMB Lateral Movement": "Lateral Movement",
        "Potential Data Exfiltration": "Data Exfiltration",
    }

    for detection in detections:
        stage_name = stage_mapping.get(detection.rule_name)

        if not stage_name:
            continue

        event = event_map[detection.event_id]

        stages.append(
            AttackStage(
                stage=stage_name,
                timestamp=event.timestamp.isoformat(),
                event_id=event.event_id,
                detection_id=detection.detection_id,
                description=detection.description,
            )
        )

    stages.sort(key=lambda stage: stage.timestamp)

    if len(stages) >= 4:
        confidence = "HIGH"
    elif len(stages) >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return AttackChain(
        incident_id=incident_id,
        attack_type="Credential Compromise",
        confidence=confidence,
        stages=stages,
    )