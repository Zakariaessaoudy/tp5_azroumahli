import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# 1. CONFIGURATION DES CHEMINS
# ==========================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "datasets")

NETWORK_FILE = os.path.join(DATASET_DIR, "network_logs.csv")
SECURITY_FILE = os.path.join(DATASET_DIR, "security_logs.csv")
SYSTEM_FILE = os.path.join(DATASET_DIR, "system_metrics.csv")
APPLICATION_FILE = os.path.join(DATASET_DIR, "application_logs.txt")
CONFIG_FILE = os.path.join(DATASET_DIR, "infrastructure_config.json")


# ==========================================
# 2. CHARGEMENT DES DONNEES
# ==========================================

def load_datasets():
    print("=" * 60)
    print("CHARGEMENT DES DONNEES - DEMOTECH AIOPS")
    print("=" * 60)

    # Chargement des fichiers CSV
    network_df = pd.read_csv(NETWORK_FILE)
    security_df = pd.read_csv(SECURITY_FILE)
    system_df = pd.read_csv(SYSTEM_FILE)

    # Lecture des journaux applicatifs
    with open(APPLICATION_FILE, "r", encoding="utf-8") as file:
        application_logs = file.readlines()

    # Chargement du fichier JSON
    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        infrastructure_config = json.load(file)

    return (
        network_df,
        security_df,
        system_df,
        application_logs,
        infrastructure_config
    )


# ==========================================
# 3. AFFICHAGE DES PREMIERES LIGNES
# ==========================================

def display_preview(datasets):
    network_df, security_df, system_df, application_logs, config = datasets

    print("\n1. NETWORK LOGS")
    print(network_df.head())

    print("\n2. SECURITY LOGS")
    print(security_df.head())

    print("\n3. SYSTEM METRICS")
    print(system_df.head())

    print("\n4. APPLICATION LOGS")
    for line in application_logs[:5]:
        print(line.strip())

    print("\n5. INFRASTRUCTURE CONFIGURATION")
    print(json.dumps(config, indent=4, ensure_ascii=False))


# ==========================================
# 4. ANALYSE DES STRUCTURES (ÉTAPE 1 - QUESTION 1)
# ==========================================

def analyze_structure(datasets):
    network_df, security_df, system_df, application_logs, config = datasets

    csv_datasets = {
        "Network Logs": network_df,
        "Security Logs": security_df,
        "System Metrics": system_df
    }

    for name, df in csv_datasets.items():
        print("\n" + "=" * 60)
        print(f"ANALYSE : {name}")
        print("=" * 60)

        print(f"Nombre d'enregistrements : {len(df)}")

        print("\nTypes des colonnes :")
        print(df.dtypes)

        print("\nInformations générales :")
        df.info()

        print("\nValeurs manquantes :")
        print(df.isnull().sum())

        print("\nNombre de doublons :")
        print(df.duplicated().sum())

    print("\nAPPLICATION LOGS")
    print(f"Nombre de lignes : {len(application_logs)}")

    print("\nINFRASTRUCTURE CONFIG")
    print(f"Type : {type(config).__name__}")

    if isinstance(config, dict):
        print("Clés disponibles :", list(config.keys()))


# ==========================================
# 5. ANALYSE DES DONNÉES RÉSEAU (ÉTAPE 1 - QUESTION 2)
# ==========================================

def analyze_network_data(network_df, save_plot=True, show_plot=False):
    """
    Réalise l'analyse demandée à la question 2 :
    - Calculer le nombre total de communications
    - Déterminer la répartition des protocoles TCP et UDP
    - Calculer la latence moyenne
    - Identifier le nombre de communications réussies, lentes et échouées
    - Calculer le taux d'échec des communications
    - Identifier les ports les plus utilisés
    - Représenter graphiquement l'évolution de la latence
    - Fournir les éléments de réponse sur la disponibilité et la performance
    """
    print("\n" + "=" * 60)
    print("2. ANALYSE DES DONNÉES RÉSEAU (network_logs.csv)")
    print("=" * 60)

    # Copie et conversion du timestamp
    df = network_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # 1. Nombre total de communications
    total_communications = len(df)
    print(f"\n[1] Nombre total de communications : {total_communications}")

    # 2. Répartition des protocoles TCP et UDP
    protocol_counts = df["protocol"].value_counts()
    protocol_percent = df["protocol"].value_counts(normalize=True) * 100
    protocol_summary = pd.DataFrame({
        "Occurrences": protocol_counts,
        "Pourcentage (%)": protocol_percent.round(2)
    })
    print("\n[2] Répartition des protocoles :")
    print(protocol_summary)

    # 3. Calcul de la latence moyenne
    mean_latency = df["latency_ms"].mean()
    median_latency = df["latency_ms"].median()
    max_latency = df["latency_ms"].max()
    min_latency = df["latency_ms"].min()
    print(f"\n[3] Latence moyenne : {mean_latency:.2f} ms")
    print(f"    (Min : {min_latency:.2f} ms | Médiane : {median_latency:.2f} ms | Max : {max_latency:.2f} ms)")

    # 4. Nombre de communications réussies, lentes et échouées
    status_counts = df["status"].value_counts()
    nb_reussies = status_counts.get("OK", 0)
    nb_lentes = status_counts.get("SLOW", 0)
    nb_echouees = status_counts.get("FAILED", 0)
    print("\n[4] Répartition des statuts des communications :")
    print(f"    - Réussies (OK)    : {nb_reussies} ({nb_reussies / total_communications * 100:.2f}%)")
    print(f"    - Lentes (SLOW)    : {nb_lentes} ({nb_lentes / total_communications * 100:.2f}%)")
    print(f"    - Échouées (FAILED): {nb_echouees} ({nb_echouees / total_communications * 100:.2f}%)")

    # 5. Calcul du taux d'échec des communications
    failure_rate = (nb_echouees / total_communications) * 100
    print(f"\n[5] Taux d'échec des communications : {failure_rate:.2f}%")

    # 6. Identifier les ports les plus utilisés
    port_mapping = {80: "HTTP (80)", 443: "HTTPS (443)", 53: "DNS (53)", 5432: "PostgreSQL (5432)"}
    port_counts = df["port"].value_counts()
    port_summary = pd.DataFrame({
        "Port": port_counts.index,
        "Service": [port_mapping.get(p, f"Port {p}") for p in port_counts.index],
        "Nombre d'appels": port_counts.values,
        "Pourcentage (%)": (df["port"].value_counts(normalize=True).values * 100).round(2)
    })
    print("\n[6] Ports les plus utilisés :")
    print(port_summary.to_string(index=False))

    # 7. Représenter graphiquement l'évolution de la latence
    plot_path = os.path.join(BASE_DIR, "latency_evolution.png")
    plt.figure(figsize=(12, 6))
    df_sorted = df.sort_values("timestamp")
    
    plt.plot(df_sorted["timestamp"], df_sorted["latency_ms"], color="tab:blue", label="Latence (ms)", linewidth=1.2)
    plt.axhline(mean_latency, color="red", linestyle="--", label=f"Moyenne ({mean_latency:.1f} ms)")
    plt.axhline(150, color="orange", linestyle=":", label="Seuil critique (150 ms)")
    
    # Mettre en évidence les statuts FAILED et SLOW
    failed_rows = df_sorted[df_sorted["status"] == "FAILED"]
    slow_rows = df_sorted[df_sorted["status"] == "SLOW"]
    if not slow_rows.empty:
        plt.scatter(slow_rows["timestamp"], slow_rows["latency_ms"], color="orange", s=30, label="Status SLOW", zorder=5)
    if not failed_rows.empty:
        plt.scatter(failed_rows["timestamp"], failed_rows["latency_ms"], color="red", s=40, marker="x", label="Status FAILED", zorder=6)

    plt.title("Évolution temporelle de la latence réseau (ms)", fontsize=14, fontweight="bold")
    plt.xlabel("Horodatage (timestamp)", fontsize=11)
    plt.ylabel("Latence (ms)", fontsize=11)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(loc="upper right")
    plt.tight_layout()

    if save_plot:
        plt.savefig(plot_path, dpi=300)
        print(f"\n[7] Graphique de l'évolution de la latence sauvegardé sous : {plot_path}")
    if show_plot:
        plt.show()
    plt.close()

    # 8. Réponse à la question théorique / d'analyse
    print("\n" + "-" * 60)
    print("[8] Réponse à la question :")
    print("« Quelles informations permettent de déterminer qu'un service réseau rencontre")
    print("  un problème de disponibilité ou de performance ? »")
    print("-" * 60)
    explanation = (
        "1. Pour la DISPONIBILITÉ :\n"
        "   - Le statut de communication : des statuts 'FAILED' indiquent une indisponibilité directe.\n"
        "   - Le taux d'échec des requêtes (ex: FAILED / Total) sur un port ou un hôte destination donné.\n"
        "   - Des erreurs de type timeout / 'Connection refused' ou absence totale de réponse.\n\n"
        "2. Pour la PERFORMANCE :\n"
        "   - La métrique de latence (latency_ms) : pics brutaux ou augmentation anormale au-delà des seuils (ex: seuil > 150 ms).\n"
        "   - Les statuts de dégradation comme 'SLOW' qui signalent des ralentissements sans rupture totale.\n"
        "   - La gigue (variation temporelle de la latence) et la saturation de requêtes sur un port spécifique.\n"
    )
    print(explanation)

    return {
        "total_communications": total_communications,
        "protocol_counts": protocol_counts.to_dict(),
        "mean_latency": mean_latency,
        "status_counts": status_counts.to_dict(),
        "failure_rate": failure_rate,
        "port_counts": port_counts.to_dict(),
        "plot_path": plot_path
    }


# ==========================================
# 6. PROGRAMME PRINCIPAL
# ==========================================

if __name__ == "__main__":
    # Chargement
    datasets = load_datasets()

    # Question 1 : Aperçu & structure
    display_preview(datasets)
    analyze_structure(datasets)

    # Question 2 : Analyse des données réseau
    network_df = datasets[0]
    analyze_network_data(network_df)

    print("\nAnalyse terminée avec succès.")
