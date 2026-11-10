"""Agent simple d'analyse des journaux applicatifs — Étape 2 du TP5."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
APPLICATION_FILE = ROOT_DIR / "datasets" / "application_logs.txt"
OUTPUT_FILE = ROOT_DIR / "outputs" / "application_agent_results.json"


def application_agent(application_logs):
    results = {
        "errors": [],
        "warnings": [],
        "recommendations": [],
    }

    # Analyse des logs
    parsed_logs = []
    for line in application_logs:
        parts = line.strip().split(" ", 3)
        if len(parts) == 4:
            parsed_logs.append({
                "timestamp": f"{parts[0]} {parts[1]}",
                "level": parts[2],
                "message": parts[3],
            })

    # Classification des événements
    results["errors"] = [log for log in parsed_logs if log["level"] == "ERROR"]
    results["warnings"] = [log for log in parsed_logs if log["level"] == "WARNING"]

    # Identification des erreurs récurrentes
    error_counts = Counter(error["message"] for error in results["errors"])
    results["recurring_errors"] = {
        message: count
        for message, count in error_counts.items()
        if count > 1
    }

    # Identification des périodes avec une concentration d'erreurs
    errors_by_hour = Counter(
        datetime.strptime(error["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:00")
        for error in results["errors"]
    )
    results["error_concentration_periods"] = {
        period: count
        for period, count in errors_by_hour.items()
        if count > 1
    }

    # Génération des recommandations
    for message in results["recurring_errors"]:
        text = message.lower()
        if "database" in text or "connection pool" in text:
            recommendation = "Vérifier la base de données, le pool de connexions et les paramètres réseau."
        elif "timeout" in text:
            recommendation = "Contrôler la latence réseau et le temps de réponse des services appelés."
        elif "configuration" in text:
            recommendation = "Vérifier les fichiers de configuration et les variables d'environnement."
        elif "http 500" in text:
            recommendation = "Consulter la trace de l'exception côté serveur et corriger l'erreur applicative."
        else:
            recommendation = "Consulter les journaux détaillés et reproduire l'erreur."

        results["recommendations"].append({
            "error": message,
            "occurrences": results["recurring_errors"][message],
            "recommendation": recommendation,
        })

    return results


def main():
    with APPLICATION_FILE.open("r", encoding="utf-8") as file:
        application_logs = file.readlines()

    results = application_agent(application_logs)

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    print(json.dumps(results, indent=4, ensure_ascii=False))
    print(f"\nRésultat enregistré dans : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
