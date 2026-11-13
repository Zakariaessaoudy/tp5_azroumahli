# Documentation Technique et Choix d'Architecture AIOps

Ce document détaille l'architecture logicielle, les choix techniques de conception et les principes multi-agents appliqués sur la plateforme AIOps DemoTech.

---

## 1. Architecture Globale du Projet

Le projet adopte une architecture modulaire et découplée, conforme aux exigences de l'énoncé :

```text
AIOps/
├── datasets/                 # Jeux de données bruts (.csv, .txt, .json)
├── agents/                   # Agents spécialisés autonomes
│   ├── network_agent.py      # Supervision des flux et latences réseau
│   ├── security_agent.py     # Supervision des accès et menaces
│   ├── system_agent.py       # Supervision des ressources système
│   └── application_agent.py  # Analyse et regroupement des erreurs applicatives
├── orchestration/
│   └── orchestrator.py       # Orchestration, corrélation croisée et module LLM
├── analysis/
│   ├── anomaly_detection.py  # Modèle Machine Learning (Isolation Forest)
│   ├── evaluation.py         # Métriques d'évaluation et de benchmark
│   └── data_analysis.py      # Analyse exploratoire et contrôle de données
├── dashboard/
│   └── app.py                # Interface utilisateur Streamlit
├── tests/                    # Tests unitaires Pytest
├── outputs/                  # Résultats JSON, graphiques générés et rapports
└── README.md                 # Guide de déploiement et d'utilisation
```

---

## 2. Choix Techniques et Justifications

### A. Découpage en Agents Spécialisés Indépendants
- **Cloisonnement des responsabilités (Single Responsibility Principle) :** Chaque agent est un expert de son domaine de données (réseau, sécurité, système, applicatif).
- **Extensibilité et tolérance aux pannes :** L'échec ou la modification d'un agent n'impacte pas l'exécution des autres.
- **Réutilisabilité :** Les agents peuvent être exécutés individuellement en ligne de commande ou invoqués par l'orchestrateur.

### B. Approche Hybride de Détection (Règles Déterministes + Machine Learning)
1. **Règles déterministes (Agents) :**
   - Comparaison directe aux seuils configurés dans `infrastructure_config.json`.
   - Garantit une réactivité immédiate et une explicabilité absolue pour les règles d'exploitation critiques (ex. CPU > 80%, 5 échecs de login).
2. **Machine Learning non supervisé (Isolation Forest) :**
   - Algorithme multivarié entraîné sur les 4 variables système (`cpu_usage`, `memory_usage`, `disk_usage`, `process_count`).
   - Isole les anomalies complexes multidimensionnelles même lorsqu'aucun seuil unitaire n'est individuellement franchi.

### C. Orchestration et Analyse Croisée d'Incidents
- **Rapprochement temporel :** L'orchestrateur agrège les événements se produisant sur des fenêtres proches pour détecter les incidents systémiques (ex. l'attaque brute force provoquant la saturation CPU du serveur web).
- **Distinction Corrélation vs Causalité :** Le système distingue une simple synchronie d'événements d'une causalité mécaniquement prouvée (ex. port base de données fermé qui engendre l'échec des requêtes SQL).

### D. Intégration Sécurisée d'un LLM
- **Grounding strict (zéro hallucination) :** Le module LLM est alimenté exclusivement par les structures de données JSON produites par les agents. Il lui est interdit d'inventer des métriques ou événements non observés.
- **Sortie JSON stricte et typée :** La réponse respecte un schéma rigoureux (`situation_summary`, `incident_classification`, `clear_explanation`, `recommendations`, `human_verification_required`).
- **Human-in-the-Loop :** Les actions critiques (bannissement d'IP, suppression de fichiers, redémarrages de base) sont formellement isolées pour approbation humaine préalable.

### E. Interface Utilisateur (Streamlit + Plotly)
- **Visualisations interactives :** Graphiques temporels avec filtres, cartes métriques d'état global (`CRITICAL`, `DEGRADED`, `HEALTHY`) et tableau dynamique des alertes.
- **Temps réel :** Capacité de rafraîchir dynamiquement l'analyse des agents via un bouton interactif.

---

## 3. Stratégie de Test et Validation

- **Pytest :** 7 tests unitaires couvrant l'ensemble des modules (calcul de latence, détection brute-force, dépassements seuils système, parsing d'erreurs applicatives et consolidation orchestrateur).
- **Évaluation continue :** Calcul automatique des indicateurs clés (Recall de détection, faux positifs, faux négatifs, temps d'exécution).

