"""Agent simple d'analyse des événements de sécurité — Étape 2 du TP5."""

import json
from pathlib import Path

import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[1]
SECURITY_FILE = ROOT_DIR / "datasets" / "security_logs.csv"
CONFIG_FILE = ROOT_DIR / "datasets" / "infrastructure_config.json"
OUTPUT_FILE = ROOT_DIR / "outputs" / "security_agent_results.json"


def security_agent(security_data, config):
    alerts = []

    # Identifier les échecs d'authentification
    failed_logins = security_data[
        (security_data["event_type"] == "LOGIN")
        & (security_data["status"] == "FAILED")
    ]

    # Regrouper les échecs par IP et par utilisateur
    failures_by_ip = failed_logins.groupby("source_ip").size()
    failures_by_user = failed_logins.groupby("username").size()

    # Appliquer les règles de détection
    threshold = config["security_rules"]["failed_login_alert_threshold"]

    for source_ip, failure_count in failures_by_ip.items():
        if failure_count >= threshold:
            concerned_users = (
                failed_logins[failed_logins["source_ip"] == source_ip]
                .groupby("username")
                .size()
                .to_dict()
            )
            alerts.append({
                "type": "REPEATED_LOGIN_FAILURES_BY_IP",
                "severity": "HIGH",
                "source_ip": source_ip,
                "failure_count": int(failure_count),
                "concerned_users": concerned_users,
                "message": f"{failure_count} échecs d'authentification depuis {source_ip}.",
                "recommendation": "Vérifier l'adresse IP et bloquer temporairement la source si l'activité est malveillante.",
            })

    for username, failure_count in failures_by_user.items():
        if failure_count >= threshold:
            alerts.append({
                "type": "REPEATED_LOGIN_FAILURES_BY_USER",
                "severity": "HIGH",
                "username": username,
                "failure_count": int(failure_count),
                "message": f"{failure_count} échecs d'authentification pour l'utilisateur {username}.",
                "recommendation": "Vérifier le compte, imposer un changement de mot de passe et rechercher une tentative de force brute.",
            })

    # Classifier les événements à forte criticité
    high_severity_events = security_data[
        security_data["severity"].isin(["HIGH", "CRITICAL"])
    ]

    if not high_severity_events.empty:
        alerts.append({
            "type": "HIGH_SEVERITY_EVENTS",
            "severity": "CRITICAL",
            "event_count": int(len(high_severity_events)),
            "events_by_type": high_severity_events["event_type"].value_counts().to_dict(),
            "source_ips": high_severity_events["source_ip"].value_counts().to_dict(),
            "message": f"{len(high_severity_events)} événement(s) de forte criticité détecté(s).",
            "recommendation": "Examiner immédiatement les événements HIGH et CRITICAL et les corréler avec les comptes et adresses IP concernés.",
        })

    return alerts


def main():
    security_data = pd.read_csv(SECURITY_FILE)

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        config = json.load(file)

    alerts = security_agent(security_data, config)

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4, ensure_ascii=False)

    print(json.dumps(alerts, indent=4, ensure_ascii=False))
    print(f"\nRésultat enregistré dans : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
