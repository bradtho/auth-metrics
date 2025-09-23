""" Application to serve Prometheus metrics with basic auth. """

import base64
import os
from flask import Flask, Response, request
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Prometheus metric
REQUEST_COUNT = Counter("my_app_requests_total", "Total requests to my app")

# Credentials (use env vars, fall back to defaults for local dev)
USERNAME = os.getenv("METRICS_USER", "prometheus")
PASSWORD = os.getenv("METRICS_PASS", "changeme")

def check_auth(auth_header):
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
    except Exception:
        return False

def authenticate():
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="metrics"'}
    )

@app.route("/")
def home():
    REQUEST_COUNT.inc()
    return "Hello, World!"

@app.route("/metrics")
def metrics():
    auth_header = request.headers.get("Authorization")
    if not check_auth(auth_header):
        return authenticate()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)