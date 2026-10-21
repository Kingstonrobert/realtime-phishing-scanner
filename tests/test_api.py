"""Unit and integration tests for FastAPI service."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    """Verify /health returns 200 and valid status structure."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model_backend" in data
    assert "cache_stats" in data


def test_scan_benign_url(client):
    """Verify /scan endpoint on benign URL."""
    payload = {"url": "https://www.nytimes.com/section/technology"}
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["url"] == payload["url"]
    assert data["classification"] == "benign"
    assert data["is_phishing"] is False
    assert 0.0 <= data["risk_score"] <= 1.0
    assert data["execution_time_ms"] < 100.0  # Must be strictly under 100ms
    assert isinstance(data["risk_factors"], list)


def test_scan_phishing_url(client):
    """Verify /scan endpoint on phishing URL."""
    payload = {"url": "http://paypal.com-verify-security.tk/login"}
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "phishing"
    assert data["is_phishing"] is True
    assert data["risk_score"] > 0.5
    assert len(data["risk_factors"]) > 0


def test_caching_behavior(client):
    """Verify that repeated requests hit the LRU cache with sub-millisecond execution."""
    test_url = "https://www.github.com/explore"
    payload = {"url": test_url}

    # First request (cold)
    r1 = client.post("/scan", json=payload)
    assert r1.status_code == 200
    d1 = r1.json()

    # Second request (cached)
    r2 = client.post("/scan", json=payload)
    assert r2.status_code == 200
    d2 = r2.json()

    assert d2["cached"] is True
    assert d2["execution_time_ms"] < d1["execution_time_ms"] or d2["execution_time_ms"] < 1.0


def test_batch_scan_endpoint(client):
    """Verify /batch-scan endpoint processes multiple URLs."""
    urls = [
        "https://www.apple.com",
        "http://appleid.apple.com-login-alert.cf/verify",
        "https://www.microsoft.com",
    ]
    response = client.post("/batch-scan", json={"urls": urls})
    assert response.status_code == 200
    data = response.json()

    assert data["total_urls"] == 3
    assert len(data["results"]) == 3
    assert data["results"][0]["classification"] == "benign"
    assert data["results"][1]["classification"] == "phishing"


def test_invalid_input_validation(client):
    """Verify validation errors on empty or missing URL."""
    res = client.post("/scan", json={"url": ""})
    assert res.status_code == 422

    res2 = client.post("/scan", json={})
    assert res2.status_code == 422


def test_cache_clear(client):
    """Verify /cache/clear clears cache items."""
    res = client.post("/cache/clear")
    assert res.status_code == 200
    data = res.json()
    assert data["stats"]["size"] == 0
