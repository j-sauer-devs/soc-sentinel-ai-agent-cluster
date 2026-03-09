"""Shared fixtures for SOC Sentinel tests."""

import pytest
from fastapi.testclient import TestClient

from server.main import app


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def sample_alert_dict():
    """A minimal alert dict for pipeline/chat tests."""
    return {
        "id": "ALERT-TEST-001",
        "source_ip": "185.220.101.34",
        "dest_ip": "10.0.1.42",
        "alert_type": "Suspicious Outbound Connection",
        "description": "C2 beaconing pattern detected",
    }
