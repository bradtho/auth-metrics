"""Application to serve Prometheus metrics with basic auth."""

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Union
import jwt
from flask import Flask, Response, request, jsonify
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Prometheus metric
REQUEST_COUNT = Counter("my_app_requests_total", "Total requests to my app")

# Credentials (use env vars, fall back to defaults for local dev)
USERNAME = os.getenv("METRICS_USER", "prometheus")
PASSWORD = os.getenv("METRICS_PASS", "changeme")

# JWT secret
JWT_SECRET = os.getenv("JWT_SECRET", "jwtsecret")
JWT_ALGORITHM = "HS256"

# Set Token Expiry
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "30"))

# AUTH HELPERS


def check_basic_auth(auth_header: str) -> bool:
    """Validate the Authorization header."""
    if not auth_header:
        return False
    try:
        scheme, credentials = auth_header.split(" ", 1)
        if scheme.lower() != "basic":
            return False

        decoded = base64.b64decode(credentials).decode("utf-8")
        user, passwd = decoded.split(":", 1)
        return user == USERNAME and passwd == PASSWORD
    except (ValueError, base64.binascii.Error):
        # Catches invalid base64 and missing ":"
        return False


def check_jwt_auth(auth_header: Optional[str]) -> Union[dict, bool, Response]:
    """Validate the JWT bearer token"""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return False
    token_value = auth_header.split(" ", 1)[1]
    try:
        decoded_payload = jwt.decode(
            token_value, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return Response("Token expired", 401)
    except jwt.InvalidTokenError:
        return False


def require_auth() -> Response:
    """Prompt for Auth"""
    return Response(
        "Authentication required", 401, {"WWW-Authenticate": 'Basic realm="metrics"'}
    )


# JWT HELPERS


def generate_token(username: str) -> str:
    """Generate a JWT for testing"""
    now = datetime.now(timezone.utc)
    payload = {"sub": username, "iat": now, "exp": now + timedelta(minutes=JWT_EXP_MIN)}
    token_str = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token_str if isinstance(token_str, str) else token_str.decode("utf-8")


def verify_token(token: str) -> dict | None:
    """Verify and decode a JWT token. Returns payload if valid, None if invalid."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ROUTES


@app.route("/")
def home():
    """Default Route."""
    REQUEST_COUNT.inc()
    return "Hello, World!"


@app.route("/metrics")
def metrics():
    """Metrics Endpoint that accepts either Basic or JWT auth."""
    auth_header = request.headers.get("Authorization")

    # Try JWT first
    payload = check_jwt_auth(auth_header)
    if isinstance(payload, Response):  # expired token
        return payload
    if payload:
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    # Fallback to Basic auth
    if not check_basic_auth(auth_header):
        return require_auth()

    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.route("/token")
def token():
    """Generate a JWT Token"""
    auth_header = request.headers.get("Authorization")
    if not check_basic_auth(auth_header):
        return require_auth()

    new_token = generate_token(USERNAME)
    return jsonify({"token": new_token, "expires_in": JWT_EXP_MIN * 60})


@app.route("/verify", methods=["POST"])
def verify():
    """Verify a JWT Token (self-check endpoint)"""
    auth_header = request.headers.get("Authorization")
    payload = check_jwt_auth(auth_header)
    if isinstance(payload, Response):
        return payload
    if payload is False:
        return jsonify({"valid": False}), 401

    return jsonify({"valid": True, "subject": payload["sub"], "payload": payload})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
