# AIOps — Plateforme de Supervision et Cybersécurité Multi-Agents

Ce projet implémente une plateforme AIOps (*Artificial Intelligence for IT Operations*) modulaire et multi-agents pour la supervision, l'administration système et la cybersécurité de l'infrastructure informatique **DemoTech**.

---

## 📌 Présentation des Étapes du TP

1. **Étape 1 : Préparation et analyse des données**
   - Chargement, exploration et validation de la qualité des données (`network_logs.csv`, `security_logs.csv`, `system_metrics.csv`, `application_logs.txt`, `infrastructure_config.json`).
   - Analyse statistique univariée : réseau, sécurité, ressources système et logs applicatifs.
   - Génération des premiers graphiques et du rapport d'analyse initial (`outputs/rapport_etape1.md`).

2. **Étape 2 : Développement des agents spécialisés**
   - Conception de 4 agents indépendants aux responsabilités cloisonnées :
     - `Network Agent` : analyse de latence, taux d'échec et services dégradés.
     - `Security Agent` : détection d'attaques par force brute et événements de forte criticité.
     - `System Administration Agent` : dépassements de seuils CPU, mémoire et disque.
     - `Application Agent` : classification des erreurs récurrentes et concentration horaire.

3. **Étape 3 : Détection intelligente des anomalies (Machine Learning)**
   - Intégration de l'algorithme non-supervisé **Isolation Forest** sur les métriques multivariées (CPU, RAM, Disque, Processus).
   - Détection des comportements anormaux hors seuils univariés et comparaison avec les règles déterministes.

4. **Étape 4 : Conception et orchestration du système multi-agents**
   - Orchestration centralisée coordonnant les agents spécialisés.
   - Analyse croisée multi-composants (rapprochement temporel, distinction corrélation vs causalité).
   - Interface d'interprétation LLM produisant un JSON structuré et identifiant les actions soumises à validation humaine ; sans client LLM configuré, un résultat déterministe clairement signalé est utilisé.

5. **Étape 5 : Développement d'une interface de supervision**
   - Dashboard interactif sous **Streamlit** présentant l'état global de l'infrastructure, les graphiques temporels (Plotly), les tableaux d'alertes et les recommandations IA.

6. **Étape 6 : Tests, validation et évaluation**
   - Tests unitaires automatisés avec `pytest` et métriques d'évaluation des performances du système.

---

## 📁 Architecture du Projet

```text
AIOps/
│
├── datasets/                 # Fichiers de données simulées et configuration
├── agents/                   # Les 4 agents spécialisés indépendants
│   ├── network_agent.py
│   ├── security_agent.py
│   ├── system_agent.py
│   └── application_agent.py
├── orchestration/            # Orchestrateur multi-agents et analyse croisée
│   └── orchestrator.py
├── analysis/                 # Analyses exploratoires et Machine Learning
│   ├── anomaly_detection.py  # Modèle Isolation Forest
│   ├── data_analysis.py      # Scripts d'analyse Étape 1
│   └── report_generator.py   # Générateur de rapport
├── dashboard/                # Interface utilisateur de supervision
│   └── app.py                # Application Streamlit
├── outputs/                  # Résultats JSON, graphiques et rapports générés
├── tests/                    # Tests unitaires Pytest
├── main.py                   # Point d'entrée principal
├── README.md                 # Documentation du projet
└── requirements.txt          # Dépendances Python
```

---

## 🚀 Installation et Lancement

### 1. Prérequis et installation des dépendances

Assurez-vous de disposer de Python 3.9+ et installez les dépendances du projet :

```bash
pip install -r requirements.txt
```

### 2. Exécution de la plateforme multi-agents

Pour exécuter l'ensemble des agents et consolider les résultats :

```bash
python main.py
```

### 3. Lancement de l'interface de supervision (Dashboard Streamlit)

Pour ouvrir l'interface graphique de supervision dans votre navigateur :

```bash
streamlit run dashboard/app.py
```

L'application sera accessible par défaut à l'adresse suivante : **`http://localhost:8501`**.

