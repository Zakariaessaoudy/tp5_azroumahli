# Rapport Global des Incidents et Recommandations AIOps

Ce rapport consolide les analyses multi-agents, les corrélations d'incidents et les recommandations opérationnelles de la plateforme **AIOps DemoTech**.

---

## 1. Synthèse de l'État Global de l'Infrastructure

- **Statut Global :** `CRITICAL`
- **Nombre total d'alertes consolidées :** 17
- **Nombre d'incidents majeurs corrélés :** 5
- **Taux de détection global :** 82.26 % (sur les anomalies système connues)

L'infrastructure présente des dégradations critiques simultanées touchant la sécurité périmétrique, la liaison avec la base de données et la saturation de stockage.

---

## 2. Incidents Majeurs Détectés et Corrélations Croisées

### Incident 1 : Attaque par Force Brute Externe & Surcharge CPU (web-server-01)
- **Composants :** `203.0.113.77` (IP externe attaquante) -> `web-server-01` (`192.168.1.10`, ports 80/443).
- **Période :** 02/11/2026 de 05:00 à 08:00.
- **Observations :**
  - 13 échecs consécutifs d'authentification ciblant le compte `admin`.
  - CPU de `web-server-01` saturé à **94.9%** (seuil 80%) avec **250 processus concurrents**.
- **Hypothèse causale :** Une attaque brute-force par dictionnaire/credential stuffing a saturé les workers web Apache/Nginx.

### Incident 2 : Coupure de Liaison Base de Données (Port 5432)
- **Composants :** `db-server-01` (`192.168.1.20`) <-> `app-server-01` (`192.168.1.30`).
- **Période :** 02/11/2026 de 11:30 à 12:40.
- **Observations :**
  - 9 communications réseau en statut `FAILED` sur le port 5432 avec latences extrêmes (~1018 ms).
  - Échecs applicatifs répétés : `Database connection failed` et `Connection pool exhausted`.
- **Hypothèse causale :** Indisponibilité du service PostgreSQL ou incident de routage/firewall bloquant la connectivité inter-serveurs.

### Incident 3 : Saturation Critique du Disque (app-server-01)
- **Composants :** `app-server-01`.
- **Période :** 03/11/2026 de 15:00 à 19:50.
- **Observations :**
  - Taux d'occupation disque atteignant **97.2%** (seuil 90%) sur 30 mesures consécutives.
- **Hypothèse causale :** Remplissage de la partition par des logs non purgés ou des fichiers temporaires volumineux.

### Incident 4 : Saturation Mémoire sur db-server-01
- **Composants :** `db-server-01`.
- **Période :** 02/11/2026 à 22:00 jusqu'au 03/11 à 01:00.
- **Observations :** Pic de RAM à **97.3%** (seuil 85%).
- **Hypothèse causale :** Fuite mémoire ou surconsommation du cache de base de données (shared_buffers).

### Incident 5 : Ralentissement Réseau et Cascade d'Erreurs 500
- **Composants :** Flux HTTP/HTTPS et PostgreSQL.
- **Période :** 01/11/2026 de 18:00 à 20:00.
- **Observations :** 12 communications réseau lentes (`SLOW`, latence > 360 ms) entraînant 19 erreurs `Request timeout` et `HTTP 500`.

---

## 3. Plan de Recommandations Opérationnelles

| Priorité | Cible | Action Recommandée | Type de validation |
| :--- | :--- | :--- | :--- |
| **P1 - IMMÉDIAT** | Pare-feu / Sécurité | Bloquer l'IP externe `203.0.113.77` et activer un rate-limiting sur l'authentification. | Validation humaine requise |
| **P1 - IMMÉDIAT** | app-server-01 | Purger les fichiers journaux et libérer l'espace disque (occupation critique à 97.2%). | Validation humaine requise |
| **P1 - IMMÉDIAT** | db-server-01 | Vérifier l'état du daemon PostgreSQL (port 5432) et réinitialiser le pool de connexions. | Automatique / Opérateur |
| **P2 - COURT TERME** | db-server-01 | Investiguer la consommation mémoire (97.3%) et optimiser les buffers PostgreSQL. | Analyse d'ingénierie |
| **P3 - MOYEN TERME** | Application | Ajuster les seuils de timeout HTTP et corriger la configuration applicative erronée. | Équipe de développement |

