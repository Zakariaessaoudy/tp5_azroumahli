"""Orchestrateur du système multi-agents AIOps — Étape 4 du TP5.

Ce module coordonne l'exécution des quatre agents spécialisés :
- network_agent
- security_agent
- system_agent
- application_agent

Il effectue la consolidation des résultats, l'analyse croisée des incidents
(corrélations temporelles, serveurs/services affectés, hypothèses causales),
détermine l'état de santé global de l'infrastructure, génère des recommandations
et enrichit l'analyse avec un composant d'interprétation LLM (générant un format JSON strict
sans métriques inventées).
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ajouter la racine du projet au sys.path si nécessaire
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd

# Import des 4 agents spécialisés selon l'architecture attendue
from agents.network_agent import network_agent
from agents.security_agent import security_agent
from agents.system_agent import system_agent
from agents.application_agent import application_agent

# Configuration des chemins
DATASETS_DIR = ROOT_DIR / "datasets"
OUTPUTS_DIR = ROOT_DIR / "outputs"
ORCHESTRATOR_OUTPUT_FILE = OUTPUTS_DIR / "orchestrator_results.json"


def load_orchestrator_data() -> tuple[dict, dict]:
    """Charge l'ensemble des données d'infrastructure et la configuration."""
    network_df = pd.read_csv(DATASETS_DIR / "network_logs.csv")
    security_df = pd.read_csv(DATASETS_DIR / "security_logs.csv")
    system_df = pd.read_csv(DATASETS_DIR / "system_metrics.csv")

    with open(DATASETS_DIR / "application_logs.txt", "r", encoding="utf-8") as file:
        application_logs = [line.rstrip("\n") for line in file if line.strip()]

    with open(DATASETS_DIR / "infrastructure_config.json", "r", encoding="utf-8") as file:
        config = json.load(file)

    data = {
        "network": network_df,
        "security": security_df,
        "system": system_df,
        "application": application_logs,
    }
    return data, config


def cross_incident_analysis(data: dict, agent_results: dict, config: dict) -> dict:
    """Question 16 : Analyse croisée des incidents multi-composants.

    - Rapproche les événements se produisant sur des fenêtres temporelles proches.
    - Compare les serveurs et les services concernés.
    - Identifie les corrélations multi-agents.
    - Génère une hypothèse explicative sans confondre corrélation et causalité.
    """
    thresholds = config["thresholds"]
    services = {int(s["port"]): s["name"] for s in config.get("services", [])}

    network = data["network"].copy()
    network["timestamp"] = pd.to_datetime(network["timestamp"])
    network = network[
        network["status"].isin(["FAILED", "SLOW"])
        | (network["latency_ms"] > thresholds["latency_ms"])
    ].copy()
    network["period"] = network["timestamp"].dt.floor("h")

    security = data["security"].copy()
    security["timestamp"] = pd.to_datetime(security["timestamp"])
    security = security[
        ((security["event_type"] == "LOGIN") & (security["status"] == "FAILED"))
        | security["severity"].isin(["HIGH", "CRITICAL"])
    ].copy()
    security["period"] = security["timestamp"].dt.floor("h")

    system = data["system"].copy()
    system["timestamp"] = pd.to_datetime(system["timestamp"])
    system = system[
        (system["cpu_usage"] > thresholds["cpu"])
        | (system["memory_usage"] > thresholds["memory"])
        | (system["disk_usage"] > thresholds["disk"])
    ].copy()
    system["period"] = system["timestamp"].dt.floor("h")

    application_rows = []
    for line in data["application"]:
        parts = line.strip().split(" ", 3)
        if len(parts) == 4 and parts[2] == "ERROR":
            application_rows.append({
                "timestamp": pd.to_datetime(f"{parts[0]} {parts[1]}"),
                "message": parts[3],
            })
    application = pd.DataFrame(application_rows)
    if not application.empty:
        application["period"] = application["timestamp"].dt.floor("h")

    periods = set(network["period"]) | set(security["period"]) | set(system["period"])
    if not application.empty:
        periods |= set(application["period"])

    correlated_incidents = []
    for period in sorted(periods):
        net = network[network["period"] == period]
        sec = security[security["period"] == period]
        sys_data = system[system["period"] == period]
        app = application[application["period"] == period] if not application.empty else application
        counts = {
            "network": len(net), "security": len(sec),
            "system": len(sys_data), "application": len(app),
        }
        active_sources = [name for name, count in counts.items() if count > 0]
        if len(active_sources) < 2:
            continue

        ports = sorted(int(port) for port in net["port"].unique())
        evidence = []
        if len(net):
            evidence.append(f"Réseau : {len(net)} anomalie(s), latence maximale {net['latency_ms'].max():.1f} ms.")
        if len(sec):
            evidence.append(f"Sécurité : {len(sec)} événement(s) suspect(s), IP {sorted(sec['source_ip'].unique().tolist())}.")
        if len(sys_data):
            evidence.append(f"Système : {len(sys_data)} dépassement(s) sur {sorted(sys_data['hostname'].unique().tolist())}.")
        if len(app):
            evidence.append(f"Application : {len(app)} erreur(s), messages {sorted(app['message'].unique().tolist())}.")

        severity = "CRITICAL" if ((net["status"] == "FAILED").any() or (sec["severity"] == "CRITICAL").any()) else "HIGH"
        incident_number = len(correlated_incidents) + 1
        correlated_incidents.append({
            "incident_id": f"INC-{incident_number:02d}",
            "title": f"Anomalies corrélées : {', '.join(active_sources)}",
            "time_window": f"{period} à {period + pd.Timedelta(hours=1)}",
            "affected_components": {
                "servers": sorted(sys_data["hostname"].unique().tolist()),
                "ips": sorted(sec["source_ip"].unique().tolist()),
                "services": [f"{services.get(port, 'UNKNOWN')} ({port})" for port in ports],
            },
            "observed_evidence": evidence,
            "correlation_analysis": "Plusieurs catégories d'anomalies apparaissent dans la même fenêtre horaire.",
            "explanatory_hypothesis": "Une cause commune est possible, mais les données disponibles ne suffisent pas à l'établir.",
            "correlation_vs_causality": "Corrélation temporelle observée uniquement ; causalité non démontrée et à vérifier humainement.",
            "severity": severity,
        })

    return {
        "correlated_incidents_count": len(correlated_incidents),
        "incidents": correlated_incidents,
        "correlation_methodology_note": (
            "Distinction corrélation vs causalité : Une corrélation temporelle indique que deux événements "
            "se produisent simultanément (ex: attaque brute force externe et CPU élevé). La causalité "
            "n'est validée comme certaine que lorsqu'un lien déterministe est prouvé (ex: port 5432 fermé -> "
            "échec de connexion SQL)."
        ),
    }


def llm_interpretation_module(structured_results: dict, config: dict, llm_function=None) -> dict:
    """Question 17 : Module d'intégration d'un LLM pour interpréter les résultats.

    Le LLM reçoit EXCLUSIVEMENT les résultats structurés des agents et produit :
    - Un résumé de la situation.
    - Une classification des incidents.
    - Une explication compréhensible.
    - Des recommandations opérationnelles.
    - Les éléments nécessitant une vérification humaine.
    Règle absolue : n'invente aucune métrique ni aucun événement.
    """
    if llm_function is not None:
        llm_input = {
            "network": structured_results["network"],
            "security": structured_results["security"],
            "system": structured_results["system"],
            "application": structured_results["application"],
            "cross_incident_analysis": structured_results["cross_incident_analysis"],
        }
        llm_output = llm_function(llm_input)
        required_keys = {
            "situation_summary", "incident_classification", "clear_explanation",
            "recommendations", "human_verification_required",
        }
        if not isinstance(llm_output, dict) or not required_keys.issubset(llm_output):
            raise ValueError("La réponse du LLM ne respecte pas le format JSON demandé.")
        return {"status": "SUCCESS", "model": "LLM externe", **llm_output}

    incidents = structured_results["cross_incident_analysis"]["incidents"]
    alerts = structured_results["consolidated_alerts"]
    classifications = [
        {
            "incident_id": incident["incident_id"],
            "category": "Corrélation multi-agents",
            "severity": incident["severity"],
            "summary": incident["title"],
        }
        for incident in incidents
    ]

    recommendations = []
    for alert in alerts:
        recommendation = alert.get("recommendation")
        if recommendation and recommendation not in [item["action"] for item in recommendations]:
            recommendations.append({
                "priority": "P1" if alert.get("severity") == "CRITICAL" else "P2",
                "target": alert.get("source", "Infrastructure"),
                "action": recommendation,
            })

    return {
        "status": "DETERMINISTIC_FALLBACK",
        "model": "Aucun LLM externe configuré",
        "situation_summary": (
            f"{len(alerts)} alerte(s) consolidée(s) et {len(incidents)} corrélation(s) "
            "temporelle(s) ont été calculées à partir des résultats structurés."
        ),
        "incident_classification": classifications,
        "clear_explanation": (
            "Les rapprochements reposent uniquement sur la présence d'anomalies dans une même fenêtre horaire. "
            "Ils ne prouvent pas une relation de causalité."
        ),
        "recommendations": recommendations,
        "human_verification_required": [
            "Confirmer chaque alerte dans les journaux sources.",
            "Vérifier les corrélations avant de conclure à une causalité.",
            "Valider toute action de blocage, suppression, redémarrage ou modification de configuration.",
        ],
    }


def infrastructure_orchestrator(data: dict, config: dict) -> dict:
    """Question 15 : Orchestrateur principal coordonnant l'ensemble des agents spécialisés.

    - Charge les données nécessaires.
    - Appelle les agents spécialisés.
    - Collecte et consolide leurs résultats.
    - Détermine l'état global de l'infrastructure.
    - Réalise l'analyse croisée des incidents.
    - Intègre l'interprétation par LLM.
    - Génère un rapport synthétique complet.
    """
    results: dict[str, Any] = {}

    # 1. Appel des agents spécialisés
    print("-> Exécution du Network Agent...")
    results["network"] = network_agent(data["network"], config)

    print("-> Exécution du Security Agent...")
    results["security"] = security_agent(data["security"], config)

    print("-> Exécution du System Administration Agent...")
    results["system"] = system_agent(data["system"], config)

    print("-> Exécution de l'Application Agent...")
    results["application"] = application_agent(data["application"])

    # 2. Consolidation des résultats et des alertes
    all_alerts = []

    # Alertes réseau
    for alert_msg in results["network"].get("alerts", []):
        all_alerts.append({
            "source": "Network Agent",
            "severity": "HIGH" if "échec" in alert_msg else "MEDIUM",
            "message": alert_msg,
        })

    # Alertes sécurité
    for sec_alert in results["security"]:
        all_alerts.append({
            "source": "Security Agent",
            "severity": sec_alert.get("severity", "MEDIUM"),
            "message": sec_alert.get("message", ""),
            "recommendation": sec_alert.get("recommendation", ""),
        })

    # Alertes système
    for sys_alert in results["system"]:
        all_alerts.append({
            "source": "System Agent",
            "severity": sys_alert.get("severity", "HIGH"),
            "message": sys_alert.get("message", ""),
            "recommendation": sys_alert.get("recommendation", ""),
        })

    # Alertes applicatives
    recurring_errs = results["application"].get("recurring_errors", {})
    if recurring_errs:
        all_alerts.append({
            "source": "Application Agent",
            "severity": "HIGH" if any("Database" in k or "500" in k for k in recurring_errs) else "MEDIUM",
            "message": f"{len(recurring_errs)} type(s) d'erreurs applicatives récurrentes détecté(s).",
            "details": recurring_errs,
        })

    results["consolidated_alerts"] = all_alerts

    # 3. Analyse croisée des incidents
    print("-> Analyse croisée multi-composants...")
    results["cross_incident_analysis"] = cross_incident_analysis(data, results, config)

    # 4. Détermination de l'état global de l'infrastructure
    critical_alerts = [a for a in all_alerts if a.get("severity") == "CRITICAL"]
    high_alerts = [a for a in all_alerts if a.get("severity") == "HIGH"]

    if critical_alerts:
        global_status = "CRITICAL"
        status_reason = f"{len(critical_alerts)} alerte(s) critique(s) active(s) nécessitant une intervention immédiate."
    elif high_alerts:
        global_status = "DEGRADED"
        status_reason = f"{len(high_alerts)} alerte(s) de niveau HIGH détectée(s)."
    else:
        global_status = "HEALTHY"
        status_reason = "Toutes les métriques et services sont dans les limites nominales."

    results["global_status"] = {
        "status": global_status,
        "reason": status_reason,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts_count": len(all_alerts),
        "critical_alerts_count": len(critical_alerts),
        "high_alerts_count": len(high_alerts),
    }

    # 5. Enrichissement et interprétation par le LLM (Question 17)
    print("-> Interprétation structurée par le LLM...")
    results["llm_interpretation"] = llm_interpretation_module(results, config)

    # 6. Génération des recommandations globales consolidées
    recommendations = []
    seen_recs = set()
    for alert in all_alerts:
        rec = alert.get("recommendation")
        if rec and rec not in seen_recs:
            recommendations.append({
                "source": alert["source"],
                "recommendation": rec,
            })
            seen_recs.add(rec)

    for app_rec in results["application"].get("recommendations", []):
        r_text = app_rec.get("recommendation")
        if r_text and r_text not in seen_recs:
            recommendations.append({
                "source": "Application Agent",
                "recommendation": f"{app_rec.get('error')}: {r_text}",
            })
            seen_recs.add(r_text)

    results["recommendations"] = recommendations

    return results


def run_orchestration():
    """Point d'entrée principal pour l'étape 4 : exécute et sauvegarde le Livrable 4."""
    print("=" * 70)
    print("ÉTAPE 4 : CONCEPTION ET ORCHESTRATION DU SYSTÈME MULTI-AGENTS")
    print("=" * 70)

    # Chargement
    data, config = load_orchestrator_data()

    # Exécution de l'orchestrateur
    results = infrastructure_orchestrator(data, config)

    # Sauvegarde du Livrable 4
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ORCHESTRATOR_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print("\n" + "=" * 70)
    print(f"ÉTAT GLOBAL DE L'INFRASTRUCTURE : {results['global_status']['status']}")
    print(f"Raison : {results['global_status']['reason']}")
    print(f"Nombre total d'alertes consolidées : {results['global_status']['total_alerts_count']}")
    print(f"Nombre d'incidents croisés identifiés : {results['cross_incident_analysis']['correlated_incidents_count']}")
    print("=" * 70)

    print(f"\nLivrable 4 enregistré avec succès dans : {ORCHESTRATOR_OUTPUT_FILE}")
    return results


if __name__ == "__main__":
    run_orchestration()
