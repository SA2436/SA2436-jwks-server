# tests/test_main.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_jwks_endpoint():
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) > 0
    assert "kid" in data["keys"][0]

def test_auth_endpoint():
    resp = client.post("/auth")
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data

def test_auth_expired():
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
