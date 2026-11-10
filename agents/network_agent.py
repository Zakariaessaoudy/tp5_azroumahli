"""Agent simple de supervision réseau — Étape 2 du TP5."""

import json
from pathlib import Path

import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[1]
NETWORK_FILE = ROOT_DIR / "datasets" / "network_logs.csv"
CONFIG_FILE = ROOT_DIR / "datasets" / "infrastructure_config.json"
OUTPUT_FILE = ROOT_DIR / "outputs" / "network_agent_results.json"


def network_agent(network_data, config):
    results = {}

    # Calcul de la latence moyenne
    mean_latency = network_data["latency_ms"].mean()
    results["mean_latency_ms"] = round(float(mean_latency), 2)

    # Calcul du taux d'échec
    total_communications = len(network_data)
    failed_communications = (network_data["status"] == "FAILED").sum()
    failure_rate = (failed_communications / total_communications) * 100

    results["total_communications"] = int(total_communications)
    results["failed_communications"] = int(failed_communications)
    results["failure_rate_percent"] = round(float(failure_rate), 2)

    # Identification des services problématiques
    latency_threshold = config["thresholds"]["latency_ms"]
    service_names = {
        service["port"]: service["name"]
        for service in config["services"]
    }
    problematic_services = []

    for port, service_data in network_data.groupby("port"):
        failed_count = int((service_data["status"] == "FAILED").sum())
        slow_count = int((service_data["status"] == "SLOW").sum())
        service_latency = float(service_data["latency_ms"].mean())

        if failed_count > 0 or slow_count > 0 or service_latency > latency_threshold:
            problematic_services.append({
                "service": service_names.get(int(port), "UNKNOWN"),
                "port": int(port),
                "mean_latency_ms": round(service_latency, 2),
                "failed_count": failed_count,
                "slow_count": slow_count,
            })

    results["problematic_services"] = problematic_services

    # Génération des alertes
    alerts = []
    for service in problematic_services:
        alerts.append(
            f"Alerte sur {service['service']} (port {service['port']}) : "
            f"{service['failed_count']} échec(s), "
            f"{service['slow_count']} communication(s) lente(s), "
            f"latence moyenne {service['mean_latency_ms']} ms."
        )

    if mean_latency > latency_threshold:
        alerts.append(
            f"La latence moyenne globale dépasse le seuil de {latency_threshold} ms."
        )

    results["alerts"] = alerts
    return results


def main():
    network_data = pd.read_csv(NETWORK_FILE)

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        config = json.load(file)

    results = network_agent(network_data, config)

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    print(json.dumps(results, indent=4, ensure_ascii=False))
    print(f"\nRésultat enregistré dans : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
