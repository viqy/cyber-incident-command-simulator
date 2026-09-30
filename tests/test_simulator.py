from fastapi.testclient import TestClient

from app.core.correlation import correlate_attack
from app.core.detection import detect_suspicious_activity
from app.core.simulator import create_credential_compromise_incident
from app.main import app


client = TestClient(app)


def test_credential_compromise_incident():
    incident = create_credential_compromise_incident()

    assert incident.incident_id == "INC-2026-0001"
    assert incident.severity == "HIGH"
    assert incident.status == "DETECTED"
    assert incident.affected_host == "WS-FIN-042"
    assert incident.affected_user == "j.smith"
    assert len(incident.events) == 7


def test_events_are_in_time_order():
    incident = create_credential_compromise_incident()

    timestamps = [event.timestamp for event in incident.events]

    assert timestamps == sorted(timestamps)


def test_detection_engine_finds_suspicious_activity():
    incident = create_credential_compromise_incident()

    detections = detect_suspicious_activity(incident.events)

    assert len(detections) == 5


def test_detection_rules():
    incident = create_credential_compromise_incident()

    detections = detect_suspicious_activity(incident.events)

    rule_names = [detection.rule_name for detection in detections]

    assert "Office Application Spawned PowerShell" in rule_names
    assert "Encoded PowerShell Command" in rule_names
    assert "Suspicious External DNS Query" in rule_names
    assert "Potential SMB Lateral Movement" in rule_names
    assert "Potential Data Exfiltration" in rule_names


def test_attack_correlation():
    incident = create_credential_compromise_incident()

    detections = detect_suspicious_activity(incident.events)

    attack_chain = correlate_attack(
        incident.incident_id,
        incident.events,
        detections,
    )

    assert attack_chain.incident_id == "INC-2026-0001"
    assert attack_chain.attack_type == "Credential Compromise"
    assert attack_chain.confidence == "HIGH"
    assert len(attack_chain.stages) == 5


def test_attack_chain_order():
    incident = create_credential_compromise_incident()

    detections = detect_suspicious_activity(incident.events)

    attack_chain = correlate_attack(
        incident.incident_id,
        incident.events,
        detections,
    )

    stages = [stage.stage for stage in attack_chain.stages]

    assert stages == [
        "Initial Execution",
        "Command Execution",
        "Command & Control",
        "Lateral Movement",
        "Data Exfiltration",
    ]


def test_api_root():
    response = client.get("/")

    assert response.status_code == 200
    assert "Cyber Incident Command Center" in response.text
    assert "text/html" in response.headers["content-type"]


def test_api_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_list_incidents():
    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.json()

    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["incident_id"] == "INC-2026-0001"


def test_api_get_incident():
    response = client.get("/api/incidents/INC-2026-0001")

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == "INC-2026-0001"
    assert data["severity"] == "HIGH"


def test_api_get_events():
    response = client.get(
        "/api/incidents/INC-2026-0001/events"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == "INC-2026-0001"
    assert len(data["events"]) == 7


def test_api_get_detections():
    response = client.get(
        "/api/incidents/INC-2026-0001/detections"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == "INC-2026-0001"
    assert len(data["detections"]) == 5


def test_api_get_attack_chain():
    response = client.get(
        "/api/incidents/INC-2026-0001/attack-chain"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == "INC-2026-0001"
    assert data["attack_type"] == "Credential Compromise"
    assert data["confidence"] == "HIGH"
    assert len(data["stages"]) == 5


def test_api_unknown_incident():
    response = client.get(
        "/api/incidents/INC-9999-9999"
    )

    assert response.status_code == 404