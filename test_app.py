"""Tests for App.py"""

import base64
import pytest
from app import app, USERNAME, PASSWORD, generate_token, JWT_SECRET, JWT_ALGORITHM
import jwt


@pytest.fixture
def client():
    """Define a testing client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def basic_auth_header(username: str, password: str) -> dict:
    """Return a properly encoded Basic Auth header."""
    credentials = f"{username}:{password}".encode("utf-8")  # bytes
    b64 = base64.b64encode(credentials).decode("utf-8")  # base64 string
    return {"Authorization": f"Basic {b64}"}


def test_generate_token_valid():
    """JWT token should be generated and decodable."""
    token = generate_token(USERNAME)
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert decoded["sub"] == USERNAME


def test_verify_token_valid(client):
    """Verify endpoint should accept a valid JWT."""
    token = generate_token(USERNAME)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/verify", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["valid"] is True
    assert data["subject"] == USERNAME


def test_verify_token_invalid(client):
    """Verify endpoint should reject an invalid JWT."""
    headers = {"Authorization": "Bearer invalid.token.value"}
    response = client.post("/verify", headers=headers)
    assert response.status_code == 401
    data = response.get_json()
    assert data["valid"] is False
    assert data.get("payload") is None


def test_token_endpoint_with_basic_auth(client):
    """Token endpoint should accept Basic Auth and return JWT."""
    headers = basic_auth_header(USERNAME, PASSWORD)
    response = client.get("/token", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    token = data.get("token")
    assert token is not None
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert decoded["sub"] == USERNAME


def test_token_endpoint_missing_auth(client):
    """Token endpoint without Basic Auth should return 401."""
    response = client.get("/token")
    assert response.status_code == 401


def test_metrics_with_jwt(client):
    """Metrics endpoint should accept a valid JWT."""
    token = generate_token(USERNAME)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/metrics", headers=headers)
    assert response.status_code == 200
    assert b"# HELP" in response.data


def test_metrics_with_basic_auth(client):
    """Metrics endpoint should accept valid Basic Auth."""
    headers = basic_auth_header(USERNAME, PASSWORD)
    response = client.get("/metrics", headers=headers)
    assert response.status_code == 200
    assert b"# HELP" in response.data


def test_metrics_missing_auth(client):
    """Metrics endpoint without auth should return 401."""
    response = client.get("/metrics")
    assert response.status_code == 401
