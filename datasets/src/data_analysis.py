
import os
import json
import pandas as pd
import numpy as np

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
# 4. ANALYSE DES STRUCTURES
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
# 5. PROGRAMME PRINCIPAL
# ==========================================

if __name__ == "__main__":

    datasets = load_datasets()

    display_preview(datasets)

    analyze_structure(datasets)

    print("\nAnalyse initiale terminée.")
