"""Module de détection intelligente des anomalies — Étape 3 du TP5.

Ce module met en œuvre l'algorithme Isolation Forest pour identifier
les anomalies multidimensionnelles sur les métriques système (system_metrics.csv),
compare les résultats obtenus avec les règles déterministes et fournit
les visualisations et éléments de réponse demandés (questions 12, 13 et Livrable 3).
"""

import json
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest

# Configuration des chemins selon l'architecture du projet
ROOT_DIR = Path(__file__).resolve().parents[1]
SYSTEM_FILE = ROOT_DIR / "datasets" / "system_metrics.csv"
CONFIG_FILE = ROOT_DIR / "datasets" / "infrastructure_config.json"
OUTPUTS_DIR = ROOT_DIR / "outputs"
PLOT_OUTPUT = OUTPUTS_DIR / "isolation_forest_anomalies.png"
RESULTS_OUTPUT = OUTPUTS_DIR / "anomaly_detection_results.json"


def prepare_data(file_path=SYSTEM_FILE):
    """Charge les données système et prépare les variables pour l'apprentissage."""
    system_data = pd.read_csv(file_path)
    system_data["timestamp"] = pd.to_datetime(system_data["timestamp"])

    # Sélection des variables requises
    features = system_data[
        ["cpu_usage", "memory_usage", "disk_usage", "process_count"]
    ]
    return system_data, features


def train_isolation_forest(features, contamination=0.05, random_state=42):
    """Entraîne l'algorithme Isolation Forest selon l'exemple de départ fourni."""
    model = IsolationForest(contamination=contamination, random_state=random_state)
    predictions = model.fit_predict(features)
    return model, predictions


def apply_anomaly_detection(system_data, contamination=0.05, random_state=42):
    """Applique Isolation Forest et ajoute la colonne 'anomaly' au DataFrame."""
    features = system_data[
        ["cpu_usage", "memory_usage", "disk_usage", "process_count"]
    ]
    model, predictions = train_isolation_forest(
        features, contamination=contamination, random_state=random_state
    )

    system_data = system_data.copy()
    system_data["anomaly"] = predictions
    # Score d'anomalie : plus il est bas/négatif, plus l'observation est anormale
    system_data["anomaly_score"] = model.decision_function(features)

    return model, system_data


def compare_with_deterministic_rules(system_data, config):
    """Compare la détection Isolation Forest avec les règles déterministes basées sur les seuils."""
    thresholds = config.get("thresholds", {})
    cpu_thresh = thresholds.get("cpu", 80)
    mem_thresh = thresholds.get("memory", 85)
    disk_thresh = thresholds.get("disk", 90)

    # Détection par règles déterministes
    system_data["rule_cpu_exceeded"] = system_data["cpu_usage"] > cpu_thresh
    system_data["rule_mem_exceeded"] = system_data["memory_usage"] > mem_thresh
    system_data["rule_disk_exceeded"] = system_data["disk_usage"] > disk_thresh
    system_data["rule_anomaly"] = (
        system_data["rule_cpu_exceeded"]
        | system_data["rule_mem_exceeded"]
        | system_data["rule_disk_exceeded"]
    )

    # Intersection et divergences
    iso_anomalies = system_data["anomaly"] == -1
    rule_anomalies = system_data["rule_anomaly"]

    both = system_data[iso_anomalies & rule_anomalies]
    iso_only = system_data[iso_anomalies & (~rule_anomalies)]
    rule_only = system_data[(~iso_anomalies) & rule_anomalies]

    comparison_summary = {
        "total_records": int(len(system_data)),
        "isolation_forest_anomalies_count": int(iso_anomalies.sum()),
        "deterministic_rules_anomalies_count": int(rule_anomalies.sum()),
        "detected_by_both": int(len(both)),
        "detected_by_isolation_forest_only": int(len(iso_only)),
        "detected_by_deterministic_rules_only": int(len(rule_only)),
        "isolation_forest_anomalies_per_host": {
            str(k): int(v)
            for k, v in system_data[iso_anomalies]["hostname"].value_counts().items()
        },
        "deterministic_rules_per_host": {
            str(k): int(v)
            for k, v in system_data[rule_anomalies]["hostname"].value_counts().items()
        },
    }

    return comparison_summary, system_data


def visualize_anomalies(system_data, output_path=PLOT_OUTPUT, save_plot=True):
    """Génère et sauvegarde la visualisation des observations détectées."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(
        "Détection d'anomalies sur les métriques système (Isolation Forest)",
        fontsize=16,
        fontweight="bold",
    )

    hosts = system_data["hostname"].unique()
    colors = {"normal": "#1f77b4", "anomaly": "#d62728"}

    # 1. CPU vs Timestamp
    ax1 = axes[0, 0]
    for host in hosts:
        sub = system_data[system_data["hostname"] == host].sort_values("timestamp")
        ax1.plot(sub["timestamp"], sub["cpu_usage"], label=f"{host} (série)", alpha=0.4, linewidth=1)
    
    anom_points = system_data[system_data["anomaly"] == -1]
    ax1.scatter(
        anom_points["timestamp"],
        anom_points["cpu_usage"],
        color=colors["anomaly"],
        s=35,
        label="Anomalie détectée",
        zorder=5,
    )
    ax1.set_title("CPU Usage (%) dans le temps")
    ax1.set_ylabel("CPU (%)")
    ax1.legend(loc="upper left", fontsize=8)
    ax1.grid(True, linestyle="--", alpha=0.5)

    # 2. Memory vs Timestamp
    ax2 = axes[0, 1]
    for host in hosts:
        sub = system_data[system_data["hostname"] == host].sort_values("timestamp")
        ax2.plot(sub["timestamp"], sub["memory_usage"], label=f"{host}", alpha=0.4, linewidth=1)
    ax2.scatter(
        anom_points["timestamp"],
        anom_points["memory_usage"],
        color=colors["anomaly"],
        s=35,
        label="Anomalie détectée",
        zorder=5,
    )
    ax2.set_title("Memory Usage (%) dans le temps")
    ax2.set_ylabel("Mémoire (%)")
    ax2.legend(loc="upper left", fontsize=8)
    ax2.grid(True, linestyle="--", alpha=0.5)

    # 3. CPU vs Process Count (Scatter multidimensionnel)
    ax3 = axes[1, 0]
    normal_points = system_data[system_data["anomaly"] == 1]
    ax3.scatter(
        normal_points["cpu_usage"],
        normal_points["process_count"],
        color=colors["normal"],
        alpha=0.4,
        s=20,
        label="Normal (1)",
    )
    ax3.scatter(
        anom_points["cpu_usage"],
        anom_points["process_count"],
        color=colors["anomaly"],
        s=40,
        label="Anomalie (-1)",
        edgecolors="black",
        linewidth=0.5,
    )
    ax3.set_title("Espace multivarié : CPU Usage vs Process Count")
    ax3.set_xlabel("CPU Usage (%)")
    ax3.set_ylabel("Process Count")
    ax3.legend()
    ax3.grid(True, linestyle="--", alpha=0.5)

    # 4. Disk Usage vs Memory Usage
    ax4 = axes[1, 1]
    ax4.scatter(
        normal_points["disk_usage"],
        normal_points["memory_usage"],
        color=colors["normal"],
        alpha=0.4,
        s=20,
        label="Normal (1)",
    )
    ax4.scatter(
        anom_points["disk_usage"],
        anom_points["memory_usage"],
        color=colors["anomaly"],
        s=40,
        label="Anomalie (-1)",
        edgecolors="black",
        linewidth=0.5,
    )
    ax4.set_title("Espace multivarié : Disk Usage vs Memory Usage")
    ax4.set_xlabel("Disk Usage (%)")
    ax4.set_ylabel("Memory Usage (%)")
    ax4.legend()
    ax4.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    if save_plot:
        plt.savefig(output_path, dpi=300)
    plt.close()


def print_answers_and_synthesis():
    """Affiche les réponses méthodologiques et techniques aux questions posées."""
    answers = """
================================================================================
REPONSES AUX QUESTIONS DE L'ETAPE 3 : DETECTION INTELLIGENTE DES ANOMALIES
================================================================================

a) Quelle est la différence entre une détection par seuil et une détection basée sur Isolation Forest ?
--------------------------------------------------------------------------------
- Détection par seuil (règles déterministes) :
  Elle analyse chaque métrique de manière univariée et statique (ex. CPU > 80%).
  Elle ignore les corrélations entre variables et ne détecte une anomalie que
  lorsqu'une limite absolue prédéfinie est franchie.
- Détection par Isolation Forest (Machine Learning non supervisé) :
  Elle analyse l'ensemble des dimensions conjointement (multivariée). L'algorithme
  isole les points rares et atypiques dans l'espace des descripteurs via des arbres
  aléatoires. Il est capable de repérer des combinaisons inhabituelles (ex. nombre
  de processus très élevé avec CPU moyen, ou comportement inhabituel hors pic absolu).

b) Pourquoi faut-il choisir soigneusement le paramètre « contamination » ?
--------------------------------------------------------------------------------
- Le paramètre 'contamination' fixe la proportion théorique d'anomalies attendues
  dans le jeu de données (ici 0.05, soit 5%).
- Un paramètre trop élevé augmente artificiellement le taux de faux positifs
  en étiquetant des variations de charge légitimes comme des anomalies.
- Un paramètre trop faible engendre des faux négatifs et ne signale pas des
  incidents subtils ou des dégradations naissantes.

c) Toutes les observations détectées comme anormales constituent-elles nécessairement des incidents ?
--------------------------------------------------------------------------------
- Non. Une observation "anormale" au sens statistique représente un écart par
  rapport à la distribution majoritaire (ex. pic de sauvegardes nocturnes, tâche
  de batch planifiée, indexation ponctuelle).
- Pour devenir un véritable "incident", l'anomalie doit provoquer un impact métier,
  une indisponibilité ou une violation de SLA (d'où l'importance de combiner ML,
  règles expertes et corrélation multi-agents).

d) Comment évaluer la qualité des résultats sans disposer d'une vérité terrain complète ?
--------------------------------------------------------------------------------
1. Analyse de pseudo-vérité terrain : croiser avec les alertes connues (ex. seuils
   franchis, journaux d'erreurs applicatifs `application_logs.txt`, échecs réseau).
2. Cohérence temporelle et temporelle croisée : vérifier si les anomalies se
   regroupent pendant des plages horaires cohérentes d'incidents.
3. Analyse de stabilité et sensibilité : tester plusieurs valeurs de contamination
   et vérifier la robustesse des points isolés.
4. Validation par des experts du domaine / Administrateurs système (SRE / SysAdmin)
   qui examinent manuellement les cas détectés par le modèle.

13. Comparaison des approches :
--------------------------------------------------------------------------------
1. Règles déterministes :
   - Avantages : Déterministes, explicables immédiatement, aucun apprentissage nécessaire,
     garantissent le respect des seuils stricts de sécurité/capacité.
   - Limites : Rigides, aveugles aux anomalies multivariées, génèrent des tempêtes
     d'alertes en cas de pic continu, nécessitent une maintenance manuelle des seuils.
2. Isolation Forest (Machine Learning) :
   - Avantages : Détection non supervisée, multivariée, capte les corrélations complexes
     et les comportements inédits sans seuil fixe manuel.
   - Limites : Sensible au paramètre de contamination, absence d'explication native
     du motif précis de l'anomalie (effet "boîte noire" partielle), faux positifs sur
     les variations normales rares.
3. Interprétation par un LLM :
   - Avantages : Contextualise en langage naturel, synthétise plusieurs sources, formule
     des hypothèses causales et des recommandations d'action pour l'opérateur.
   - Limites : Risque d'hallucination si non contraint, coût d'inférence et latence,
     ne remplace pas le calcul numérique pur de détection.
================================================================================
"""
    print(answers)


def run_pipeline():
    """Exécute l'ensemble du pipeline de l'Étape 3 et sauvegarde le livrable 3."""
    print("=" * 70)
    print("ÉTAPE 3 : DÉTECTION INTELLIGENTE DES ANOMALIES (ISOLATION FOREST)")
    print("=" * 70)

    # 1. Chargement et préparation
    system_data, features = prepare_data()
    print(f"Données chargées : {len(system_data)} enregistrements.")
    print(f"Variables sélectionnées : {list(features.columns)}")

    # 2. Entraînement et détection avec Isolation Forest
    model, system_data_analyzed = apply_anomaly_detection(
        system_data, contamination=0.05, random_state=42
    )

    anomalies_detected = (system_data_analyzed["anomaly"] == -1).sum()
    normals_detected = (system_data_analyzed["anomaly"] == 1).sum()
    print(f"\nRésultats Isolation Forest (contamination=0.05) :")
    print(f" - Observations normales (1)  : {normals_detected}")
    print(f" - Observations anormales (-1): {anomalies_detected} (5.00%)")

    # 3. Chargement de la configuration et comparaison avec les règles déterministes
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)

    comparison_summary, analyzed_df = compare_with_deterministic_rules(
        system_data_analyzed, config
    )

    print("\nComparaison avec les règles déterministes :")
    print(f" - Anomalies détectées par règles seules : {comparison_summary['detected_by_deterministic_rules_only']}")
    print(f" - Anomalies détectées par Isolation Forest seul : {comparison_summary['detected_by_isolation_forest_only']}")
    print(f" - Anomalies confirmées par les deux approches : {comparison_summary['detected_by_both']}")

    # 4. Visualisation
    visualize_anomalies(analyzed_df, output_path=PLOT_OUTPUT, save_plot=True)
    print(f"\nGraphique sauvegardé dans : {PLOT_OUTPUT}")

    # 5. Sauvegarde des résultats du Livrable 3
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    anomalies_sample = analyzed_df[analyzed_df["anomaly"] == -1][
        ["timestamp", "hostname", "cpu_usage", "memory_usage", "disk_usage", "process_count", "anomaly_score"]
    ].copy()
    anomalies_sample["timestamp"] = anomalies_sample["timestamp"].astype(str)

    livrable_3 = {
        "model": "IsolationForest",
        "parameters": {"contamination": 0.05, "random_state": 42},
        "features": list(features.columns),
        "comparison_summary": comparison_summary,
        "sample_detected_anomalies": anomalies_sample.head(20).to_dict(orient="records"),
    }

    with open(RESULTS_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(livrable_3, f, indent=4, ensure_ascii=False)
    print(f"Livrable 3 (résultats structurés) enregistré dans : {RESULTS_OUTPUT}")

    # 6. Affichage des réponses aux questions
    print_answers_and_synthesis()


if __name__ == "__main__":
    run_pipeline()

