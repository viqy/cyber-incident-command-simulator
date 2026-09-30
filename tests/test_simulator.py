from datetime import datetime

from fastapi.testclient import TestClient

from app.api.investigation import router as investigation_router
from app.database.database import get_connection, initialize_database
from app.main import app


client = TestClient(app)


INCIDENT_ID = "INC-2026-0001"


def reset_database():
    connection = get_connection()

    try:
        connection.execute("DELETE FROM actions")
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM investigations")
        connection.commit()
    finally:
        connection.close()


def setup_function():
    initialize_database()
    reset_database()


def test_incident_creation():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == INCIDENT_ID
    assert data["name"] == "Credential Compromise Simulation"
    assert data["severity"] == "HIGH"
    assert data["status"] == "DETECTED"


def test_incident_contains_expected_events():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/events"
    )

    assert response.status_code == 200

    events = response.json()["events"]

    assert len(events) == 7
    assert events[0]["event_id"] == "EVT-0001"
    assert events[-1]["event_id"] == "EVT-0007"


def test_event_order():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/events"
    )

    events = response.json()["events"]

    timestamps = [
        datetime.fromisoformat(event["timestamp"])
        for event in events
    ]

    assert timestamps == sorted(timestamps)


def test_detections_are_generated():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/detections"
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    assert len(detections) == 5


def test_detection_rules():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/detections"
    )

    detections = response.json()["detections"]

    rules = [
        detection["rule_name"]
        for detection in detections
    ]

    assert "Office Application Spawned PowerShell" in rules
    assert "Encoded PowerShell Command" in rules
    assert "Suspicious External DNS Query" in rules
    assert "Potential SMB Lateral Movement" in rules
    assert "Potential Data Exfiltration" in rules


def test_attack_chain():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/attack-chain"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == INCIDENT_ID
    assert data["attack_type"] == "Credential Compromise"
    assert data["confidence"] == "HIGH"
    assert len(data["stages"]) == 5


def test_attack_chain_stage_order():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/attack-chain"
    )

    stages = response.json()["stages"]

    stage_names = [
        stage["stage"]
        for stage in stages
    ]

    assert stage_names == [
        "Initial Execution",
        "Command Execution",
        "Command & Control",
        "Lateral Movement",
        "Data Exfiltration",
    ]


def test_investigation_created():
    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/investigation"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == INCIDENT_ID
    assert data["status"] == "DETECTED"
    assert data["analyst"] is None
    assert data["findings"] == []
    assert data["actions"] == []


def test_unknown_investigation():
    response = client.get(
        "/api/incidents/INC-9999/investigation"
    )

    assert response.status_code == 404


def test_status_update():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/status",
        json={
            "status": "TRIAGED"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "TRIAGED"


def test_invalid_status():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/status",
        json={
            "status": "INVALID_STATUS"
        },
    )

    assert response.status_code == 400


def test_status_persists():
    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/status",
        json={
            "status": "INVESTIGATING"
        },
    )

    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/investigation"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "INVESTIGATING"


def test_finding_creation():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/findings",
        json={
            "finding": "Encoded PowerShell execution detected."
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["findings"]) == 1
    assert (
        data["findings"][0]
        == "Encoded PowerShell execution detected."
    )


def test_blank_finding():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/findings",
        json={
            "finding": "   "
        },
    )

    assert response.status_code == 400


def test_multiple_findings():
    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/findings",
        json={
            "finding": "Finding one."
        },
    )

    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/findings",
        json={
            "finding": "Finding two."
        },
    )

    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/investigation"
    )

    data = response.json()

    assert len(data["findings"]) == 2


def test_action_creation():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "Victor",
            "target": "WS-FIN-042",
            "reason": "Contain suspected compromised workstation.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["actions"]) == 1
    assert data["actions"][0]["action_id"] == "ACT-0001"
    assert data["actions"][0]["action_type"] == "ISOLATE_HOST"
    assert data["actions"][0]["target"] == "WS-FIN-042"
    assert data["actions"][0]["status"] == "COMPLETED"


def test_multiple_actions():
    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "Victor",
            "target": "WS-FIN-042",
            "reason": "Contain compromised workstation.",
        },
    )

    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "DISABLE_ACCOUNT",
            "performed_by": "Victor",
            "target": "j.smith",
            "reason": "Prevent further account abuse.",
        },
    )

    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/investigation"
    )

    data = response.json()

    assert len(data["actions"]) == 2
    assert data["actions"][0]["action_id"] == "ACT-0001"
    assert data["actions"][1]["action_id"] == "ACT-0002"


def test_invalid_action():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "INVALID_ACTION",
            "performed_by": "Victor",
            "target": "WS-FIN-042",
            "reason": "Testing invalid action.",
        },
    )

    assert response.status_code == 400


def test_blank_performed_by():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "   ",
            "target": "WS-FIN-042",
            "reason": "Contain host.",
        },
    )

    assert response.status_code == 400


def test_blank_target():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "Victor",
            "target": "   ",
            "reason": "Contain host.",
        },
    )

    assert response.status_code == 400


def test_blank_reason():
    response = client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "Victor",
            "target": "WS-FIN-042",
            "reason": "   ",
        },
    )

    assert response.status_code == 400


def test_action_persists():
    client.post(
        f"/api/incidents/{INCIDENT_ID}/investigation/actions",
        json={
            "action_type": "ISOLATE_HOST",
            "performed_by": "Victor",
            "target": "WS-FIN-042",
            "reason": "Contain compromised workstation.",
        },
    )

    response = client.get(
        f"/api/incidents/{INCIDENT_ID}/investigation"
    )

    data = response.json()

    assert len(data["actions"]) == 1
    assert data["actions"][0]["action_type"] == "ISOLATE_HOST"