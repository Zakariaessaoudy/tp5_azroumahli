"""Etape 1 du TP5 : préparation et analyse des données DemoTech."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT_DIR / "outputs"
MPL_CACHE_DIR = OUTPUT_DIR / ".matplotlib"
MPL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPL_CACHE_DIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


DATASET_DIR = ROOT_DIR / "datasets"

NETWORK_FILE = DATASET_DIR / "network_logs.csv"
SECURITY_FILE = DATASET_DIR / "security_logs.csv"
SYSTEM_FILE = DATASET_DIR / "system_metrics.csv"
APPLICATION_FILE = DATASET_DIR / "application_logs.txt"
CONFIG_FILE = DATASET_DIR / "infrastructure_config.json"

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>INFO|WARNING|ERROR)\s+(?P<message>.+)$"
)


def load_datasets():
    """Charge les cinq sources et retourne un dictionnaire homogène."""
    with APPLICATION_FILE.open(encoding="utf-8") as file:
        application_logs = [line.rstrip("\n") for line in file]
    with CONFIG_FILE.open(encoding="utf-8") as file:
        config = json.load(file)

    return {
        "network": pd.read_csv(NETWORK_FILE),
        "security": pd.read_csv(SECURITY_FILE),
        "system": pd.read_csv(SYSTEM_FILE),
        "application": application_logs,
        "config": config,
    }


def display_preview(data):
    """Affiche les cinq premières lignes de chaque source."""
    print("\n" + "=" * 72)
    print("1. CHARGEMENT ET APERÇU DES DONNÉES")
    print("=" * 72)
    for key in ("network", "security", "system"):
        print(f"\n{key.upper()}\n{data[key].head().to_string(index=False)}")
    print("\nAPPLICATION\n" + "\n".join(data["application"][:5]))
    print("\nCONFIGURATION\n" + json.dumps(data["config"], indent=2, ensure_ascii=False))


def analyze_structure(data):
    """Contrôle volumes, types, valeurs manquantes et doublons."""
    results = {}
    for key in ("network", "security", "system"):
        df = data[key]
        result = {
            "records": len(df),
            "dtypes": df.dtypes.astype(str).to_dict(),
            "missing": df.isna().sum().to_dict(),
            "duplicates": int(df.duplicated().sum()),
        }
        results[key] = result
        print(f"\nStructure {key}: {result['records']} enregistrements")
        print("Types:", result["dtypes"])
        print("Valeurs manquantes:", result["missing"])
        print("Doublons:", result["duplicates"])
    results["application"] = {"records": len(data["application"])}
    results["config"] = {"keys": list(data["config"].keys())}
    return results


def _save_line_plot(df, x, y, group, title, ylabel, output_path, thresholds=None):
    """Crée un graphique temporel simple, avec une courbe par groupe."""
    plt.figure(figsize=(12, 6))
    for name, part in df.sort_values(x).groupby(group):
        plt.plot(part[x], part[y], linewidth=1.2, label=str(name))
    for value, label, color in thresholds or []:
        plt.axhline(value, linestyle="--", color=color, label=label)
    plt.title(title)
    plt.xlabel("Horodatage")
    plt.ylabel(ylabel)
    plt.grid(alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def analyze_network_data(network_df, config):
    """Question 2 : analyse des communications réseau."""
    df = network_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    total = len(df)
    status_counts = df["status"].value_counts()
    port_counts = df["port"].value_counts()
    latency_mean = float(df["latency_ms"].mean())
    OUTPUT_DIR.mkdir(exist_ok=True)
    plot_path = OUTPUT_DIR / "latency_evolution.png"

    plt.figure(figsize=(12, 6))
    ordered = df.sort_values("timestamp")
    plt.plot(ordered["timestamp"], ordered["latency_ms"], linewidth=1.1)
    plt.axhline(latency_mean, color="tab:green", linestyle="--", label=f"Moyenne: {latency_mean:.1f} ms")
    threshold = config["thresholds"]["latency_ms"]
    plt.axhline(threshold, color="tab:red", linestyle="--", label=f"Seuil: {threshold} ms")
    plt.title("Évolution de la latence réseau")
    plt.xlabel("Horodatage")
    plt.ylabel("Latence (ms)")
    plt.grid(alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(plot_path, dpi=200)
    plt.close()

    results = {
        "total_communications": total,
        "protocol_counts": df["protocol"].value_counts().to_dict(),
        "mean_latency_ms": latency_mean,
        "status_counts": status_counts.to_dict(),
        "failure_rate_percent": float(status_counts.get("FAILED", 0) / total * 100),
        "port_counts": port_counts.to_dict(),
        "plot_path": str(plot_path),
    }
    print("\n" + "=" * 72 + "\n2. ANALYSE RÉSEAU\n" + "=" * 72)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print("Disponibilité: surveiller FAILED, le taux d'échec et les timeouts.")
    print("Performance: surveiller la latence, SLOW et les dépassements du seuil configuré.")
    return results


def analyze_security_events(security_df, config):
    """Question 3 : analyse des authentifications et événements de sécurité."""
    df = security_df.copy()
    login_events = df[df["event_type"].eq("LOGIN")]
    successful = int(login_events["status"].eq("SUCCESS").sum())
    failed = login_events[login_events["status"].eq("FAILED")]
    threshold = int(config.get("security_rules", {}).get("failed_login_alert_threshold", 5))
    failures_by_ip = failed.groupby("source_ip").size().sort_values(ascending=False)
    repeated_ips = failures_by_ip[failures_by_ip >= threshold]

    OUTPUT_DIR.mkdir(exist_ok=True)
    severity_plot_path = OUTPUT_DIR / "security_severity_distribution.png"
    severity_counts = df["severity"].value_counts()
    severity_order = [level for level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") if level in severity_counts]
    severity_counts = severity_counts.reindex(severity_order)
    severity_colors = {"INFO": "tab:blue", "LOW": "tab:green", "MEDIUM": "tab:orange", "HIGH": "tab:red", "CRITICAL": "darkred"}
    plt.figure(figsize=(9, 5))
    bars = plt.bar(severity_counts.index, severity_counts.values, color=[severity_colors[level] for level in severity_counts.index])
    plt.bar_label(bars, padding=3)
    plt.title("Répartition des événements de sécurité par criticité")
    plt.xlabel("Criticité")
    plt.ylabel("Nombre d'événements")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(severity_plot_path, dpi=200)
    plt.close()

    results = {
        "successful_authentications": successful,
        "failed_authentications": int(len(failed)),
        "failed_users": failed["username"].value_counts().to_dict(),
        "events_by_source_ip": df["source_ip"].value_counts().to_dict(),
        "failed_authentications_by_ip": failures_by_ip.to_dict(),
        "repeated_failure_threshold": threshold,
        "ips_with_repeated_failures": repeated_ips.to_dict(),
        "severity_distribution": severity_counts.to_dict(),
        "severity_plot_path": str(severity_plot_path),
    }
    print("\n" + "=" * 72 + "\n3. ANALYSE DES ÉVÉNEMENTS DE SÉCURITÉ\n" + "=" * 72)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(
        "Une succession d'échecs peut révéler une attaque par force brute, une tentative "
        "de credential stuffing ou un compte compromis. Elle doit être corrélée dans le "
        "temps avec l'IP, l'utilisateur et les éventuels succès qui suivent."
    )
    return results


def analyze_system_resources(system_df, config):
    """Question 4 : statistiques par serveur et dépassements de seuils."""
    df = system_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    thresholds = config["thresholds"]
    cpu_mean = df.groupby("hostname")["cpu_usage"].mean().sort_values(ascending=False)
    memory_mean = df.groupby("hostname")["memory_usage"].mean().sort_values(ascending=False)
    disk_max_by_server = df.groupby("hostname")["disk_usage"].max().sort_values(ascending=False)
    highest_disk_server = str(disk_max_by_server.index[0])

    breaches = df[
        (df["cpu_usage"] > thresholds["cpu"])
        | (df["memory_usage"] > thresholds["memory"])
        | (df["disk_usage"] > thresholds["disk"])
    ].copy()
    breaches["exceeded_thresholds"] = breaches.apply(
        lambda row: ", ".join(
            label
            for label, threshold_key, column in (
                ("CPU", "cpu", "cpu_usage"),
                ("memory", "memory", "memory_usage"),
                ("disk", "disk", "disk_usage"),
            )
            if row[column] > thresholds[threshold_key]
        ),
        axis=1,
    )

    OUTPUT_DIR.mkdir(exist_ok=True)
    plot_path = OUTPUT_DIR / "cpu_evolution.png"
    _save_line_plot(
        df,
        "timestamp",
        "cpu_usage",
        "hostname",
        "Évolution de l'utilisation CPU par serveur",
        "CPU (%)",
        plot_path,
        [(thresholds["cpu"], f"Seuil CPU: {thresholds['cpu']} %", "tab:red")],
    )
    results = {
        "mean_cpu_by_server": cpu_mean.round(2).to_dict(),
        "mean_memory_by_server": memory_mean.round(2).to_dict(),
        "max_disk_by_server": disk_max_by_server.round(2).to_dict(),
        "highest_disk_server": highest_disk_server,
        "highest_disk_percent": float(disk_max_by_server.iloc[0]),
        "threshold_breach_count": int(len(breaches)),
        "threshold_breaches": breaches[
            ["timestamp", "hostname", "cpu_usage", "memory_usage", "disk_usage", "exceeded_thresholds"]
        ].assign(timestamp=lambda x: x["timestamp"].astype(str)).to_dict("records"),
        "plot_path": str(plot_path),
    }
    print("\n" + "=" * 72 + "\n4. ANALYSE DES RESSOURCES SYSTÈME\n" + "=" * 72)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return results


def parse_application_logs(lines):
    """Transforme les lignes applicatives valides en DataFrame."""
    events = []
    malformed = []
    for line in lines:
        match = LOG_PATTERN.match(line.strip())
        if match:
            events.append(match.groupdict())
        elif line.strip():
            malformed.append(line)
    df = pd.DataFrame(events, columns=["timestamp", "level", "message"])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df, malformed


def classify_error(message):
    """Regroupe les messages d'erreur dans des catégories explicites."""
    text = message.lower()
    rules = {
        "Timeout": ("timeout", "timed out"),
        "Base de données": ("database", "sql", "connection pool"),
        "Authentification": ("authentication", "unauthorized", "login"),
        "Réseau": ("network", "connection refused", "dns"),
        "Erreur HTTP 5xx": ("http 500", "http 502", "http 503", "http 504"),
        "Configuration": ("configuration", "config invalid"),
        "Ressource indisponible": ("unavailable", "not found", "service down"),
    }
    for category, keywords in rules.items():
        if any(keyword in text for keyword in keywords):
            return category
    return "Autre"


def analyze_application_logs(lines):
    """Question 5 : extraction, comptage, regroupement et graphique des logs."""
    df, malformed = parse_application_logs(lines)
    level_counts = df["level"].value_counts().reindex(["INFO", "WARNING", "ERROR"], fill_value=0)
    errors = df[df["level"].eq("ERROR")].copy()
    errors["error_type"] = errors["message"].map(classify_error)
    message_counts = errors["message"].value_counts()
    type_counts = errors["error_type"].value_counts()

    OUTPUT_DIR.mkdir(exist_ok=True)
    plot_path = OUTPUT_DIR / "application_error_frequency.png"
    plt.figure(figsize=(10, 5))
    if not type_counts.empty:
        type_counts.sort_values().plot(kind="barh", color="tab:red")
    plt.title("Fréquence des erreurs applicatives par type")
    plt.xlabel("Nombre d'erreurs")
    plt.ylabel("Type")
    plt.tight_layout()
    plt.savefig(plot_path, dpi=200)
    plt.close()

    results = {
        "parsed_events": int(len(df)),
        "malformed_lines": len(malformed),
        "level_counts": level_counts.to_dict(),
        "most_frequent_error_messages": message_counts.to_dict(),
        "errors_by_type": type_counts.to_dict(),
        "plot_path": str(plot_path),
    }
    print("\n" + "=" * 72 + "\n5. ANALYSE DES JOURNAUX APPLICATIFS\n" + "=" * 72)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return results


def run_step1():
    """Exécute toutes les questions de l'étape 1 et retourne les résultats."""
    data = load_datasets()
    display_preview(data)
    results = {
        "structure": analyze_structure(data),
        "network": analyze_network_data(data["network"], data["config"]),
        "security": analyze_security_events(data["security"], data["config"]),
        "system": analyze_system_resources(data["system"], data["config"]),
        "application": analyze_application_logs(data["application"]),
    }
    return results


if __name__ == "__main__":
    from analysis.report_generator import generate_step1_report

    generate_step1_report(run_step1())
