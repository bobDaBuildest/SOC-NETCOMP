"""
Automated tests for the AI SOC Dashboard backend.
Run with:  pytest tests/ -v
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# ── Health ────────────────────────────────────────────────────────────────────

def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "running" in r.json()["status"]


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Anomaly Detection ─────────────────────────────────────────────────────────

NORMAL_LOG = {
    "timestamp": "2026-03-06T10:00:00",
    "source_ip": "192.168.1.10",
    "dest_ip": "8.8.8.8",
    "protocol": "TCP",
    "bytes_sent": 1500,
    "bytes_received": 3000,
    "duration": 1.2,
    "flags": "SYN ACK",
}

SUSPICIOUS_LOG = {
    "timestamp": "2026-03-06T10:01:00",
    "source_ip": "192.168.1.55",
    "dest_ip": "185.220.101.5",
    "protocol": "ICMP",
    "bytes_sent": 15_000_000,
    "bytes_received": 100,
    "duration": 0.3,
    "flags": "SYN",
}


def test_detect_normal_log():
    r = client.post("/api/detect", json=NORMAL_LOG)
    assert r.status_code == 200
    data = r.json()
    assert "is_anomaly" in data
    assert "confidence" in data
    assert "threat_level" in data
    assert data["is_anomaly"] is False


def test_detect_suspicious_log():
    r = client.post("/api/detect", json=SUSPICIOUS_LOG)
    assert r.status_code == 200
    data = r.json()
    assert data["is_anomaly"] is True
    assert data["threat_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert data["confidence"] > 0.5


def test_detect_batch():
    r = client.post("/api/detect/batch", json=[NORMAL_LOG, SUSPICIOUS_LOG])
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 2
    assert data["anomalies"] >= 1


# ── Stats ─────────────────────────────────────────────────────────────────────

def test_stats():
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_processed" in data
    assert "anomaly_rate" in data
    # Stats should reflect previous test calls
    assert data["total_processed"] > 0


# ── AI Analyst ────────────────────────────────────────────────────────────────

def test_analyze_alert_no_key(monkeypatch):
    """Should return explanation even without real API key."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-invalid")
    r = client.post("/api/analyze", json={
        "alert_id": "ALT-001",
        "alert_description": "Large outbound data transfer detected from 192.168.1.55"
    })
    # Should not crash — either returns explanation or error message
    assert r.status_code == 200
    data = r.json()
    assert "explanation" in data
    assert len(data["explanation"]) > 5
