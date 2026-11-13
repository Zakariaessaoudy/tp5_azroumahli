"""Tests unitaires pour l'Agent Réseau (Question 20 du TP5)."""

import pandas as pd
import pytest
from agents.network_agent import network_agent


@pytest.fixture
def sample_config():
    return {
        "thresholds": {"latency_ms": 150},
        "services": [
            {"name": "HTTP", "port": 80, "protocol": "TCP"},
            {"name": "HTTPS", "port": 443, "protocol": "TCP"},
            {"name": "DATABASE", "port": 5432, "protocol": "TCP"},
        ],
    }


def test_mean_latency_calculation(sample_config):
    """Test unitaire pour le calcul de la latence moyenne."""
    data = pd.DataFrame({
        "timestamp": ["2026-11-01 08:00:00", "2026-11-01 08:05:00", "2026-11-01 08:10:00"],
        "source_ip": ["192.168.1.10", "192.168.1.20", "192.168.1.10"],
        "destination_ip": ["192.168.1.30", "192.168.1.20", "192.168.1.30"],
        "protocol": ["TCP", "TCP", "TCP"],
        "port": [80, 443, 80],
        "status": ["OK", "OK", "OK"],
        "latency_ms": [50.0, 100.0, 150.0],
    })

    results = network_agent(data, sample_config)

    # (50 + 100 + 150) / 3 = 100.0 ms
    assert results["mean_latency_ms"] == 100.0
    assert results["total_communications"] == 3
    assert results["failed_communications"] == 0
    assert results["failure_rate_percent"] == 0.0


def test_network_failure_detection(sample_config):
    """Test unitaire de la détection des échecs et alertes réseau."""
    data = pd.DataFrame({
        "timestamp": ["2026-11-01 08:00:00", "2026-11-01 08:05:00"],
        "source_ip": ["192.168.1.10", "192.168.1.20"],
        "destination_ip": ["192.168.1.30", "192.168.1.20"],
        "protocol": ["TCP", "TCP"],
        "port": [5432, 5432],
        "status": ["FAILED", "OK"],
        "latency_ms": [800.0, 50.0],
    })

    results = network_agent(data, sample_config)

    assert results["failed_communications"] == 1
    assert results["failure_rate_percent"] == 50.0
    assert len(results["problematic_services"]) == 1
    assert results["problematic_services"][0]["service"] == "DATABASE"
    assert len(results["alerts"]) >= 1

