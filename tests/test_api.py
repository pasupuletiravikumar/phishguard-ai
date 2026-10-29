import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "machine_learning" in data

def test_scan_url_endpoint(client):
    response = client.post("/api/scan/url", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "url"
    assert "risk_score" in data
    assert "severity" in data
    assert "findings" in data
    assert "url_details" in data

def test_scan_email_endpoint(client):
    payload = {
        "content": "URGENT: Please verify your account immediately at http://bank.com.fake/login",
        "sender": "security@fakebank.com",
        "subject": "Immediate action required"
    }
    response = client.post("/api/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "email"
    assert data["risk_score"] > 25

def test_scan_message_endpoint(client):
    payload = {
        "message": "USPS: Your parcel is on hold. Pay $1.99 now at http://bit.ly/fake-postal",
        "source_hint": "sms"
    }
    response = client.post("/api/scan/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "message"
    assert data["severity"] in ("HIGH", "CRITICAL")

def test_oversized_payload_rejected(client):
    huge_text = "A" * 160000
    response = client.post("/api/scan/email", json={"content": huge_text})
    assert response.status_code == 413

def test_history_and_dashboard_stats(client):
    # Perform a scan first
    client.post("/api/scan/url", json={"url": "https://example.com"})

    hist_resp = client.get("/api/scan/history")
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    assert len(history) > 0

    stats_resp = client.get("/api/dashboard/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_scans"] > 0
