"""Tests unitaires pour l'Agent Système (Question 20 du TP5)."""

import pandas as pd
import pytest
from agents.system_agent import system_agent


@pytest.fixture
def sample_config():
    return {
        "thresholds": {
            "cpu": 80.0,
            "memory": 85.0,
            "disk": 90.0,
        }
    }


def test_system_threshold_exceeded(sample_config):
    """Test unitaire pour le dépassement des seuils du système (CPU, mémoire, disque)."""
    data = pd.DataFrame({
        "timestamp": [
            "2026-11-01 08:00:00",
            "2026-11-01 08:10:00",
            "2026-11-01 08:20:00",
        ],
        "hostname": ["web-server-01", "web-server-01", "db-server-01"],
        "cpu_usage": [88.5, 92.0, 45.0],
        "memory_usage": [50.0, 55.0, 89.0],
        "disk_usage": [60.0, 62.0, 70.0],
        "process_count": [150, 200, 120],
    })

    alerts = system_agent(data, sample_config)

    # 1 alerte CPU pour web-server-01 (max 92.0 > 80.0)
    cpu_alerts = [a for a in alerts if a.get("type") == "CPU_THRESHOLD_EXCEEDED"]
    assert len(cpu_alerts) == 1
    assert cpu_alerts[0]["hostname"] == "web-server-01"
    assert cpu_alerts[0]["maximum_value_percent"] == 92.0
    assert cpu_alerts[0]["severity"] == "CRITICAL"  # 92 >= 80 + 10

    # 1 alerte Mémoire pour db-server-01 (max 89.0 > 85.0)
    mem_alerts = [a for a in alerts if a.get("type") == "MEMORY_THRESHOLD_EXCEEDED"]
    assert len(mem_alerts) == 1
    assert mem_alerts[0]["hostname"] == "db-server-01"
    assert mem_alerts[0]["maximum_value_percent"] == 89.0
    assert mem_alerts[0]["severity"] == "HIGH"

