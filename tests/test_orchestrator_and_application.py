"""Tests unitaires pour l'Agent Applicatif et l'Orchestrateur (Question 20 du TP5)."""

import pytest
from agents.application_agent import application_agent
from orchestration.orchestrator import infrastructure_orchestrator
import pandas as pd


def test_application_agent_error_identification():
    """Test unitaire d'identification des erreurs applicatives et récurrences."""
    sample_logs = [
        "2026-11-01 08:00:00 INFO Service started",
        "2026-11-01 08:05:00 WARNING Latency high",
        "2026-11-01 08:10:00 ERROR Database connection failed",
        "2026-11-01 08:15:00 ERROR Database connection failed",
        "2026-11-01 08:20:00 ERROR HTTP 500 Internal Server Error",
    ]

    results = application_agent(sample_logs)

    assert len(results["errors"]) == 3
    assert len(results["warnings"]) == 1
    assert "Database connection failed" in results["recurring_errors"]
    assert results["recurring_errors"]["Database connection failed"] == 2
    assert len(results["recommendations"]) >= 1


def test_orchestrator_consolidation():
    """Test unitaire de consolidation des résultats par l'orchestrateur."""
    data = {
        "network": pd.DataFrame({
            "timestamp": ["2026-11-01 08:00:00"],
            "source_ip": ["192.168.1.10"],
            "destination_ip": ["192.168.1.20"],
            "protocol": ["TCP"],
            "port": [80],
            "status": ["OK"],
            "latency_ms": [40.0],
        }),
        "security": pd.DataFrame({
            "timestamp": ["2026-11-01 08:00:00"],
            "username": ["admin"],
            "source_ip": ["192.168.1.50"],
            "event_type": ["LOGIN"],
            "status": ["SUCCESS"],
            "severity": ["INFO"],
        }),
        "system": pd.DataFrame({
            "timestamp": ["2026-11-01 08:00:00"],
            "hostname": ["web-server-01"],
            "cpu_usage": [40.0],
            "memory_usage": [50.0],
            "disk_usage": [60.0],
            "process_count": [120],
        }),
        "application": [
            "2026-11-01 08:00:00 INFO Normal operation",
        ],
    }

    config = {
        "thresholds": {"cpu": 80, "memory": 85, "disk": 90, "latency_ms": 150},
        "services": [{"name": "HTTP", "port": 80, "protocol": "TCP"}],
        "security_rules": {"failed_login_alert_threshold": 5},
    }

    consolidated = infrastructure_orchestrator(data, config)

    assert "network" in consolidated
    assert "security" in consolidated
    assert "system" in consolidated
    assert "application" in consolidated
    assert "global_status" in consolidated
    assert consolidated["global_status"]["status"] == "HEALTHY"
    assert "llm_interpretation" in consolidated

