from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_jwks_endpoint():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) > 0
    assert "kid" in data["keys"][0]

def test_auth_endpoint():
    response = client.post("/auth")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data

def test_auth_expired():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
