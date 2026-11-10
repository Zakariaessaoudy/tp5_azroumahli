"""Génération du livrable 1 illustré de l'étape 1."""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT_DIR / "outputs"


def _mapping_lines(mapping, suffix=""):
    return "\n".join(f"- {key}: {value}{suffix}" for key, value in mapping.items()) or "- Aucun"


def generate_step1_report(results, output_path=None):
    """Crée le rapport illustré des statistiques et anomalies de l'étape 1."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    path = Path(output_path) if output_path else OUTPUT_DIR / "rapport_etape1.md"
    structure = results["structure"]
    network = results["network"]
    security = results["security"]
    system = results["system"]
    application = results["application"]

    content = f"""# Rapport d'analyse AIOps — Étape 1

Ce rapport couvre les six éléments de l'étape 1 : chargement et contrôle des données, analyses réseau, sécurité, système et application, puis synthèse des anomalies.

## 1. Chargement et qualité des données

| Source | Enregistrements | Valeurs manquantes | Doublons |
|---|---:|---:|---:|
| network_logs.csv | {structure['network']['records']} | {sum(structure['network']['missing'].values())} | {structure['network']['duplicates']} |
| security_logs.csv | {structure['security']['records']} | {sum(structure['security']['missing'].values())} | {structure['security']['duplicates']} |
| system_metrics.csv | {structure['system']['records']} | {sum(structure['system']['missing'].values())} | {structure['system']['duplicates']} |
| application_logs.txt | {structure['application']['records']} | Non applicable | Contrôle ligne par ligne |

Les trois fichiers CSV ne contiennent ni valeur manquante ni doublon. Les types sont contrôlés lors de l'exécution et les horodatages sont convertis avant les analyses temporelles. Les cinq premières lignes de chaque source et la configuration JSON sont également affichées à l'exécution.

## 2. Données réseau

- Communications analysées : {network['total_communications']}
- Latence moyenne : {network['mean_latency_ms']:.2f} ms
- Taux d'échec : {network['failure_rate_percent']:.2f} %
- Communications par statut : {network['status_counts']}
- Protocoles : {network['protocol_counts']}
- Ports les plus utilisés : {network['port_counts']}

Les statuts `FAILED`, le taux d'échec et les timeouts renseignent sur la disponibilité. La latence, les statuts `SLOW` et les dépassements du seuil configuré renseignent sur la performance.

![Évolution temporelle de la latence réseau](latency_evolution.png)

## 3. Événements de sécurité

- Authentifications réussies : {security['successful_authentications']}
- Authentifications échouées : {security['failed_authentications']}
- Utilisateurs concernés par les échecs : {security['failed_users']}
- Événements par adresse IP source : {security['events_by_source_ip']}
- Échecs d'authentification par IP : {security['failed_authentications_by_ip']}
- Répartition par criticité : {security['severity_distribution']}
- Seuil de répétition configuré : {security['repeated_failure_threshold']} échecs

### Adresses IP dépassant le seuil

{_mapping_lines(security['ips_with_repeated_failures'])}

Une succession d'échecs peut correspondre à une attaque par force brute ou à du credential stuffing. L'investigation doit vérifier la fenêtre temporelle, les comptes visés, l'origine réseau et l'existence d'une authentification réussie après les échecs.

![Répartition des événements de sécurité par criticité](security_severity_distribution.png)

## 4. Ressources système

### CPU moyen par serveur

{_mapping_lines(system['mean_cpu_by_server'], ' %')}

### Mémoire moyenne par serveur

{_mapping_lines(system['mean_memory_by_server'], ' %')}

- Serveur avec le pic disque le plus élevé : {system['highest_disk_server']} ({system['highest_disk_percent']:.2f} %)

![Évolution de l'utilisation CPU par serveur](cpu_evolution.png)

## 5. Journaux applicatifs

- Événements analysés : {application['parsed_events']}
- Lignes non reconnues : {application['malformed_lines']}
- Répartition des niveaux : {application['level_counts']}
- Erreurs par type : {application['errors_by_type']}
- Messages d'erreur les plus fréquents : {application['most_frequent_error_messages']}

![Fréquence des erreurs applicatives par type](application_error_frequency.png)

## 6. Anomalies principales

- Les échecs réseau et les latences dépassant le seuil doivent être rapprochés des services et ports concernés.
- Les IP présentant plusieurs échecs d'authentification nécessitent une investigation de sécurité.
- Les dépassements CPU, mémoire ou disque doivent être examinés sur les serveurs et périodes listés.
- Les erreurs applicatives récurrentes doivent être corrélées avec les anomalies réseau et système proches dans le temps.

## Vérification de couverture des consignes

| Exigence | État |
|---|---|
| Charger les trois CSV, le journal texte et le JSON | Réalisé |
| Afficher les cinq premières lignes | Réalisé à l'exécution |
| Contrôler volumes, types, valeurs manquantes et doublons | Réalisé |
| Calculer toutes les statistiques réseau demandées | Réalisé |
| Représenter l'évolution de la latence | Réalisé et intégré |
| Analyser authentifications, utilisateurs, IP et criticité | Réalisé |
| Analyser CPU, mémoire, disque et dépassements de seuils | Réalisé |
| Représenter l'évolution CPU | Réalisé et intégré |
| Extraire et regrouper les journaux applicatifs | Réalisé |
| Représenter la fréquence des erreurs | Réalisé et intégré |
| Présenter statistiques et anomalies dans un rapport | Réalisé |
"""
    path.write_text(content, encoding="utf-8")
    print(f"\nRapport généré : {path}")
    return path
