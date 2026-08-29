import pytest
from fastapi.testclient import TestClient
from src.api.main import app, ADMIN_KEY, API_KEY

client = TestClient(app)

def test_admin_status_unauthorized():
    response = client.get("/admin/status")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid Admin key"}

def test_admin_status_with_invalid_key():
    response = client.get("/admin/status", headers={"x-admin-key": "wrong-key"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid Admin key"}

def test_admin_status_success():
    response = client.get("/admin/status", headers={"x-admin-key": ADMIN_KEY})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["component"] == "C2-DynamicPlanner"
    assert data["admin_authenticated"] is True

def test_kb_update_unauthorized():
    payload = {
        "content": "Nmap stealth scanning documentation for security testing.",
        "metadata": {"tool": "nmap"}
    }
    response = client.post("/kb/update", json=payload)
    assert response.status_code == 401

def test_kb_update_success():
    payload = {
        "content": "Custom security tool documentation chunk for testing administrative dynamic updates.",
        "metadata": {"tool": "custom_test_tool"}
    }
    response = client.post("/kb/update", json=payload, headers={"x-admin-key": ADMIN_KEY})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["chunks_added"] >= 1
    assert "kb_chunks" in data

def test_admin_metrics_reset():
    response = client.post("/admin/metrics/reset", headers={"x-admin-key": ADMIN_KEY})
    assert response.status_code == 200
    assert response.json() == {"status": "success", "message": "Metrics reset successfully"}

def test_admin_session_clear():
    response = client.post("/admin/session/clear?session_id=test-session-123", headers={"x-admin-key": ADMIN_KEY})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["session_id"] == "test-session-123"
