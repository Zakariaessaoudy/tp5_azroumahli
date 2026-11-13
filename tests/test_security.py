"""Tests unitaires pour l'Agent de Sécurité (Question 20 du TP5)."""

import pandas as pd
import pytest
from agents.security_agent import security_agent


@pytest.fixture
def sample_config():
    return {
        "security_rules": {
            "failed_login_alert_threshold": 3
        }
    }


def test_repeated_login_failures_detection(sample_config):
    """Test unitaire pour la détection des échecs répétés d'authentification."""
    data = pd.DataFrame({
        "timestamp": [
            "2026-11-01 08:00:00",
            "2026-11-01 08:01:00",
            "2026-11-01 08:02:00",
            "2026-11-01 08:03:00",
        ],
        "username": ["admin", "admin", "admin", "analyst"],
        "source_ip": ["203.0.113.77", "203.0.113.77", "203.0.113.77", "192.168.1.50"],
        "event_type": ["LOGIN", "LOGIN", "LOGIN", "LOGIN"],
        "status": ["FAILED", "FAILED", "FAILED", "SUCCESS"],
        "severity": ["LOW", "LOW", "LOW", "INFO"],
    })

    alerts = security_agent(data, sample_config)

    # L'IP 203.0.113.77 a 3 échecs, ce qui atteint le seuil de 3
    ip_alerts = [a for a in alerts if a.get("type") == "REPEATED_LOGIN_FAILURES_BY_IP"]
    assert len(ip_alerts) == 1
    assert ip_alerts[0]["source_ip"] == "203.0.113.77"
    assert ip_alerts[0]["failure_count"] == 3


def test_high_severity_event_classification(sample_config):
    """Test de la détection et classification des événements critiques."""
    data = pd.DataFrame({
        "timestamp": ["2026-11-01 09:00:00"],
        "username": ["admin"],
        "source_ip": ["203.0.113.77"],
        "event_type": ["PRIVILEGE_ESCALATION"],
        "status": ["FAILED"],
        "severity": ["CRITICAL"],
    })

    alerts = security_agent(data, sample_config)

    crit_alerts = [a for a in alerts if a.get("type") == "HIGH_SEVERITY_EVENTS"]
    assert len(crit_alerts) == 1
    assert crit_alerts[0]["severity"] == "CRITICAL"

