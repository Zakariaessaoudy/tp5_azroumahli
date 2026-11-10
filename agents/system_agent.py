"""Agent simple de supervision des ressources système — Étape 2 du TP5."""

import json
from pathlib import Path

import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[1]
SYSTEM_FILE = ROOT_DIR / "datasets" / "system_metrics.csv"
CONFIG_FILE = ROOT_DIR / "datasets" / "infrastructure_config.json"
OUTPUT_FILE = ROOT_DIR / "outputs" / "system_agent_results.json"


def system_agent(system_data, config):
    alerts = []
    thresholds = config["thresholds"]

    # Analyser CPU
    resources = [
        ("CPU", "cpu_usage", thresholds["cpu"]),
        ("MEMORY", "memory_usage", thresholds["memory"]),
        ("DISK", "disk_usage", thresholds["disk"]),
    ]

    # Analyser mémoire et disque, puis générer les recommandations
    for resource_name, column, threshold in resources:
        exceeded_data = system_data[system_data[column] > threshold]

        for hostname, server_data in exceeded_data.groupby("hostname"):
            maximum_value = float(server_data[column].max())
            severity = "CRITICAL" if maximum_value >= threshold + 10 else "HIGH"

            recommendations = {
                "CPU": "Identifier les processus consommateurs et répartir la charge.",
                "MEMORY": "Rechercher une fuite mémoire et libérer ou augmenter la mémoire disponible.",
                "DISK": "Supprimer ou archiver les fichiers inutiles et augmenter l'espace disque si nécessaire.",
            }

            alerts.append({
                "type": f"{resource_name}_THRESHOLD_EXCEEDED",
                "severity": severity,
                "hostname": hostname,
                "threshold_percent": float(threshold),
                "maximum_value_percent": round(maximum_value, 2),
                "exceeded_measurement_count": int(len(server_data)),
                "first_detection": str(server_data["timestamp"].min()),
                "last_detection": str(server_data["timestamp"].max()),
                "message": f"Le seuil {resource_name} est dépassé sur {hostname}.",
                "recommendation": recommendations[resource_name],
            })

    return alerts


def main():
    system_data = pd.read_csv(SYSTEM_FILE)

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        config = json.load(file)

    alerts = system_agent(system_data, config)

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4, ensure_ascii=False)

    print(json.dumps(alerts, indent=4, ensure_ascii=False))
    print(f"\nRésultat enregistré dans : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
