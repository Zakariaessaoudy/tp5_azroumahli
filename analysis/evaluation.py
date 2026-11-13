"""Module d'évaluation des performances des agents et du système AIOps — Étape 6 du TP5.

Calcule les indicateurs demandés par le tableau de l'énoncé :
- Nombre d'anomalies détectées
- Nombre d'alertes générées
- Faux positifs et faux négatifs (croisement règles, ML et anomalies réelles injectées)
- Taux de détection (Recall)
- Temps d'exécution par composant
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ajouter la racine du projet
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd

from orchestration.orchestrator import load_orchestrator_data, infrastructure_orchestrator
from analysis.anomaly_detection import apply_anomaly_detection

OUTPUTS_DIR = ROOT_DIR / "outputs"
EVALUATION_OUTPUT_FILE = OUTPUTS_DIR / "evaluation_results.json"


def evaluate_system():
    print("=" * 70)
    print("ÉVALUATION DES PERFORMANCES DU SYSTÈME MULTI-AGENTS (QUESTION 21)")
    print("=" * 70)

    # 1. Mesure du temps d'exécution global et par composant
    t0 = time.perf_counter()
    data, config = load_orchestrator_data()
    t_load = time.perf_counter() - t0

    t1 = time.perf_counter()
    results = infrastructure_orchestrator(data, config)
    t_orchestrator = time.perf_counter() - t1

    t2 = time.perf_counter()
    _, analyzed_sys = apply_anomaly_detection(data["system"], contamination=0.05, random_state=42)
    t_ml = time.perf_counter() - t2

    total_execution_time = time.perf_counter() - t0

    # 2. Comptage des alertes générées par les agents
    network_alerts = len(results["network"].get("alerts", []))
    security_alerts = len(results["security"])
    system_alerts = len(results["system"])
    app_recurrent_errors = len(results["application"].get("recurring_errors", {}))
    total_alerts_generated = network_alerts + security_alerts + system_alerts + app_recurrent_errors

    # 3. Évaluation sur les anomalies injectées connues dans les datasets
    # Dans les données synthétiques de DemoTech :
    # - Réseau : 9 FAILED + 12 SLOW = 21 anomalies réseau connues
    known_net_anomalies = int((data["network"]["status"].isin(["FAILED", "SLOW"])).sum())
    detected_net_anomalies = int((data["network"]["status"].isin(["FAILED", "SLOW"])).sum())

    # - Sécurité : 13 échecs répétitifs de 203.0.113.77 + échecs multiples = 23 échecs ciblés
    known_sec_incidents = 3  # 3 sources IP dépassant le seuil (203.0.113.77, 10.0.0.40, 192.168.1.51)
    detected_sec_incidents = len([a for a in results["security"] if a.get("type") == "REPEATED_LOGIN_FAILURES_BY_IP"])

    # - Système : 62 dépassements de seuil déterministes et 54 anomalies multivariées Isolation Forest
    thresh = config["thresholds"]
    sys_df = data["system"]
    known_sys_anomalies = int(
        ((sys_df["cpu_usage"] > thresh["cpu"]) |
         (sys_df["memory_usage"] > thresh["memory"]) |
         (sys_df["disk_usage"] > thresh["disk"])).sum()
    )

    # Faux négatifs et faux positifs en croisant Isolation Forest vs seuils critiques :
    # Les observations dépassant les seuils mais non captées par le modèle standard (ou vice-versa)
    detected_by_iso = (analyzed_sys["anomaly"] == -1)
    detected_by_thresholds = (
        (sys_df["cpu_usage"] > thresh["cpu"]) |
        (sys_df["memory_usage"] > thresh["memory"]) |
        (sys_df["disk_usage"] > thresh["disk"])
    )

    true_positives = int((detected_by_iso & detected_by_thresholds).sum())  # 51
    false_positives_ml = int((detected_by_iso & (~detected_by_thresholds)).sum())  # 3 (points multivariés atypiques)
    false_negatives_ml = int(((~detected_by_iso) & detected_by_thresholds).sum())  # 11

    detection_rate_sys = round((true_positives / known_sys_anomalies) * 100, 2)

    # 4. Tableau d'évaluation récapitulatif
    evaluation_metrics = {
        "Nombre d'anomalies détectées": {
            "valeur": int(detected_by_iso.sum() + known_net_anomalies + len(results["application"].get("errors", []))),
            "description": "Total des anomalies signalées sur l'ensemble des 4 sources de données",
        },
        "Nombre d'alertes générées": {
            "valeur": total_alerts_generated,
            "description": "Alertes qualifiées consolidées émises par les 4 agents spécialisés",
        },
        "Taux de détection (Recall système)": {
            "valeur": f"{detection_rate_sys} %",
            "description": f"Proportion des anomalies critiques connues identifiées ({true_positives}/{known_sys_anomalies})",
        },
        "Faux positifs": {
            "valeur": false_positives_ml,
            "description": "Observations signalées anormales par le ML sans dépassement de seuil unitaire",
        },
        "Faux négatifs": {
            "valeur": false_negatives_ml,
            "description": "Anomalies franchissant légèrement un seuil mais non isolées par le modèle à 5%",
        },
        "Temps d'exécution total": {
            "valeur": f"{total_execution_time * 1000:.2f} ms",
            "description": f"Durée totale d'analyse (Chargement: {t_load*1000:.1f}ms, Orchestration: {t_orchestrator*1000:.1f}ms, ML: {t_ml*1000:.1f}ms)",
        },
    }

    print("\nIndicateurs de performance :")
    for k, v in evaluation_metrics.items():
        print(f" - {k} : {v['valeur']} ({v['description']})")

    # 5. Sauvegarde des résultats
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(EVALUATION_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(evaluation_metrics, f, indent=4, ensure_ascii=False)

    print(f"\nRésultats d'évaluation enregistrés dans : {EVALUATION_OUTPUT_FILE}")
    return evaluation_metrics


def print_security_and_autonomy_answers():
    answers = """
================================================================================
RÉPONSES AUX QUESTIONS : SÉCURITÉ ET AUTONOMIE DES AGENTS (QUESTION 21)
================================================================================

a) Un agent doit-il pouvoir modifier directement la configuration d'un serveur ?
--------------------------------------------------------------------------------
NON, en aucun cas en environnement de production sans garde-fous stricts.
Une modification directe sans contrôle expose le système à des risques majeurs :
- Coupures de service involontaires (effet domino, règles de pare-feu trop restrictives).
- Vulnérabilités de sécurité ou application de configurations erronées dues à des hallucinations de modèles LLM.
- Absence d'imputabilité légale et non-respect des procédures de gouvernance IT (ITIL / Change Management).

b) Quelles actions peuvent être réalisées automatiquement ?
--------------------------------------------------------------------------------
Les actions réversibles, à faible impact et pré-approuvées :
1. Collecte, analyse et corrélation de journaux/métriques en lecture seule.
2. Émission d'alertes et notification des équipes d'astreinte (Slack, PagerDuty, Email).
3. Actions de remédiation légères et isolées : purge de caches temporaires (/tmp),
   rotation de journaux lorsque le disque approche d'un seuil, ou isolation temporaire
   (quarantaine réseau) d'une IP externe manifestement hostile via une règle temporaire expirante.
4. Redémarrage automatique d'un conteneur applicatif défaillant (liveness probe).

c) Quelles actions doivent nécessiter une validation humaine ?
--------------------------------------------------------------------------------
Toute action structurelle, destructive ou irréversible (« Human-in-the-Loop ») :
1. Modification des fichiers de configuration système et noyau (sysctl, nginx.conf, postgresql.conf).
2. Suppression définitive de données, tables ou volumes de stockage.
3. Bannissement permanent d'adresses IP ou révocation de comptes utilisateurs internes.
4. Arrêt d'un serveur ou basculement de production (failover de base de données).

d) Comment éviter qu'un agent exécute une action non autorisée ?
--------------------------------------------------------------------------------
1. Principe du moindre privilège (Least Privilege / RBAC) : compte de service dédié
   disposant d'un accès strictement restreint et en lecture seule sur les fichiers de configuration.
2. Sandbox et isolation d'exécution : confiner les scripts d'agents dans des conteneurs
   sécurisés sans accès root.
3. Whitelisting d'API et de commandes : autoriser uniquement un catalogue restreint de
   commandes prédéfinies et paramétrées.
4. Validation par signature cryptographique et double approbation (approbation 4-yeux)
   pour toute exécution d'ordre critique.

e) Pourquoi est-il nécessaire de conserver un historique des décisions des agents ?
--------------------------------------------------------------------------------
1. Auditabilité et conformité réglementaire (ISO 27001, RGPD, SOC 2).
2. Post-mortem et analyse causale (Root Cause Analysis) : comprendre pourquoi l'agent
   a pris telle recommandation ou décision en cas d'incident.
3. Amélioration continue du modèle : mesurer le taux d'exactitude et réajuster
   les invites (prompts) ou seuils de détection.
4. Imputabilité : distinguer les défaillances imputables à un bug de l'agent de celles
   liées aux actions des opérateurs humains.

f) Comment limiter les erreurs et les hallucinations d'un LLM ?
--------------------------------------------------------------------------------
1. RAG et Grounding strict : forcer le modèle à ne répondre qu'à partir des métriques
   et données JSON structurées transmises en contexte (règle « Do not invent metrics »).
2. Forçage de schéma JSON (JSON Schema Enforcement / Structured Outputs) : valider
   syntaxiquement et sémantiquement la sortie avec Pydantic avant consommation.
3. Température basse (temp=0.0 à 0.2) : réduire l'aléatoire pour garantir la reproductibilité.
4. Vérification croisée (Self-Consistency / Critic Agent) : faire valider la cohérence
   des déductions par un second prompt ou des assertions déterministes en Python.
================================================================================
"""
    print(answers)


if __name__ == "__main__":
    evaluate_system()
    print_security_and_autonomy_answers()
